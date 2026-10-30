#!/usr/bin/env bash
# Pull Docker Hub images through mirror.gcr.io: the one copy of the step that
# points the runner's Docker daemon at Google's cache of Docker Hub before a
# job pulls or builds from a Docker Hub image. Docker Hub answers an anonymous
# pull with HTTP 429 once the limit every runner behind one address shares is
# spent (OPEN 49), and the daemon falls back to Docker Hub itself for anything
# the mirror cannot serve, so this can only remove failures; a digest-pinned
# pull is still checked against its digest, whichever host serves it.
#
# Run by tenant CI's container job (platform-ci.yml, which copies it out of
# its mirror checkout into $RUNNER_TEMP and removes that checkout before the
# build context is read), the nightly safety sweep before its first Trivy run
# (safety-sweep.yml) and ci.yml's registry-mirror-smoke, which proves it on a
# real runner with Docker Hub blocked before the mirror publishes it. Until
# v0.17.3 the three held three copies of this text, kept equal by a lint
# (R7-9). Restarting the daemon is safe in each: no container has started in
# those jobs yet.
#
# Never a gate: a file that is not a JSON object is left as it is, a daemon
# that will not restart with the mirror gets its original file back, and a
# missing mirror warns. Each of those leaves Docker Hub direct, as before.
# Only a daemon that stays down fails here, where the cause is visible.
#
# Usage: bash ci/registry-mirror.sh
# -e alone, the shell an Actions run step gets: no pipefail, because the
# buildx probe below may fail and must leave the driver empty, not stop.
set -e

conf=/etc/docker/daemon.json
mirror=https://mirror.gcr.io
work="$(mktemp -d)"
had_conf=false
if sudo test -f "$conf"; then
  had_conf=true
  sudo cat "$conf" > "$work/before.json"
else
  echo '{}' > "$work/before.json"
fi
# Merge, never overwrite: the runner image keeps its own settings in
# this file (its cgroup parent, for one).
if ! jq --arg m "$mirror" '.["registry-mirrors"] = ([$m] + ((.["registry-mirrors"] // []) - [$m]))' "$work/before.json" > "$work/after.json" 2>/dev/null \
  || ! jq -e 'type == "object"' "$work/after.json" >/dev/null 2>&1; then
  echo "::warning title=Registry mirror::$conf is not a JSON object this step can merge into; left as it is, so Docker Hub images are pulled directly"
  exit 0
fi
sudo mkdir -p "$(dirname "$conf")"
sudo cp "$work/after.json" "$conf"
# docker.service has TimeoutStartSec=0, so a restart that hangs would
# hold the step for the job's whole timeout: each one is bounded.
if ! sudo timeout 120 systemctl restart docker; then
  if [ "$had_conf" = true ]; then sudo cp "$work/before.json" "$conf"; else sudo rm -f "$conf"; fi
  # A unit that failed to start is rate-limited from restarting again.
  sudo systemctl reset-failed docker || true
  sudo timeout 120 systemctl restart docker || true
  if ! docker info >/dev/null 2>&1; then
    echo "::error title=Docker daemon::the Docker daemon did not come back after its configuration was restored; nothing in this job can build or scan the image"
    exit 1
  fi
  echo "::warning title=Registry mirror::the Docker daemon would not restart with $mirror as a registry mirror; restored its configuration, so Docker Hub images are pulled directly"
  exit 0
fi
# The runner image keeps a Docker Hub credential in the CLI's config. The
# daemon forwards it to the mirror, which refuses it ("authentication
# failed"), and the pull falls back to Docker Hub. Without that one entry
# the mirror pulls are anonymous, which the mirror serves; a fallback pull
# is then anonymous too, as the build's base-image pulls already were.
cli_conf="$HOME/.docker/config.json"
if [ -f "$cli_conf" ]; then
  if jq 'if (.auths? | type) == "object" then .auths |= with_entries(select(.key | test("(^|//)(index[.])?docker[.]io(/|$)") | not)) else . end' "$cli_conf" > "$work/cli.json" 2>/dev/null; then
    cp "$work/cli.json" "$cli_conf"
    echo "dropped the Docker Hub entry from $cli_conf, so pulls through the mirror are anonymous"
  else
    echo "::warning title=Registry mirror::$cli_conf is not JSON this step can edit; the mirror refuses the Docker Hub credential it holds, so Docker Hub images are pulled directly"
  fi
fi
mirrors="$(docker info --format '{{json .RegistryConfig.Mirrors}}' 2>/dev/null || true)"
echo "docker daemon registry mirrors: ${mirrors:-none}"
case "$mirrors" in
  *"$mirror"*) ;;
  *) echo "::warning title=Registry mirror::the Docker daemon does not list $mirror after the restart, so Docker Hub images are pulled directly" ;;
esac
driver="$(docker buildx inspect 2>/dev/null | sed -n 's/^Driver: *//p' | head -n 1)"
echo "docker build builder: ${driver:-the classic builder}"
if [ -n "$driver" ] && [ "$driver" != docker ]; then
  echo "::warning title=Registry mirror::docker build uses the $driver buildx driver, which does not read the daemon's registry mirrors, so base images are pulled directly"
fi
