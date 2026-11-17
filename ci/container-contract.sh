#!/usr/bin/env bash
# The container contract for tenant CI's container job (APP-CONTRACT R2 and
# R7-5), one check per step of the job:
#   container-contract.sh user     "Assert non-root user + EXPOSE 8080"
#   container-contract.sh healthz  "Smoke test /healthz"
# Both read the image the build step tagged app-under-test. A refusal is a
# plain line on stderr and then one "Container contract" annotation from
# ci/annotate.mjs, run from this script's own directory: the job copies this
# script, annotate.mjs and the cli.mjs it imports out of its mirror checkout
# into $RUNNER_TEMP/ci and removes that checkout before the app checkout,
# whose root is the build context (v0.18.16, CI-02; the checks were the two
# steps' inline bodies until then).
#
# Usage: container-contract.sh <user|healthz>; any other argument exits 2.
set -euo pipefail
ci="$(cd "${0%/*}" && pwd -P)"

# Config.User and EXPOSE: the image runs as a non-root uid Docker reads the
# way this allowlist does, and listens on 8080.
user() {
  # An ALLOWLIST, not a model of Docker's parser. Docker resolves
  # Config.User with moby/sys/user and then casts to uint32, and that
  # path reads many malformed inputs as uid 0: a signed "+0", an empty
  # user part (":1000"), a passwd uid field that is not a plain number
  # ("abc", "0 ", empty), a passwd line it trims but awk would skip, and
  # a uid that wraps past 2^32 (review C1, v0.14.4). So the gate accepts
  # exactly two shapes and refuses everything else:
  #   1. a plain decimal uid from 1 to 2147483647 (Docker's own maximum);
  #   2. a portable user name ([A-Za-z0-9._-], not starting with "-")
  #      that appears on exactly one /etc/passwd line, and on no other
  #      line once leading and trailing blanks are trimmed, where that
  #      line's uid field is a plain decimal from 1 to 2147483647.
  # Only the user part before the first ":" is checked; the group never
  # makes the process uid 0.
  #
  # NUL bytes are turned into \001 before anything reaches a shell
  # variable: bash drops NULs silently, which would turn "1<NUL>0"
  # (uid 0 to Docker) into "10".
  user="$(docker inspect --format='{{.Config.User}}' app-under-test | tr '\000' '\001')"
  # What the messages print: Config.User with anything outside
  # printable ASCII shown as "?", so a line break in it cannot write a
  # workflow command into the log, and the runner's old command
  # marker "##[" broken to "## [", as ci/cli.mjs logSafe breaks it,
  # since the runner acts on it anywhere in a line. Each refusal's
  # plain line is followed by its "Container contract" annotation
  # (R7-5), from the helper beside this script.
  shown="$(printf '%s' "$user" | LC_ALL=C tr -c ' -~' '?' | sed 's/##\[/## [/g')"
  refuse() {
    echo "container-validate: User='$shown' $1" >&2
    node "$ci/annotate.mjs" --title "Container contract" --file Dockerfile \
      --what "container-validate: User='$shown' $1" \
      --fix "run as a non-root user (a USER with a numeric UID other than 0 in the Dockerfile)"
    exit 1
  }
  # `0:0` and `root:root` are neither "", "root" nor "0", so the old
  # three-way compare passed them while docker still ran the image as
  # uid 0 (review F16). Kept as the first, cheapest refusal.
  case "$user" in
    0|root|0:*|root:*|"")
      refuse "runs as root, refusing"
      ;;
  esac
  user_part="${user%%:*}"
  case "$user_part" in
    "")
      refuse "has an empty user part, which Docker runs as uid 0, refusing"
      ;;
    *[!0123456789]*)
      case "$user_part" in
        -*|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-]*)
          refuse "is neither a plain uid nor a portable user name ([A-Za-z0-9._-], not starting with -), refusing"
          ;;
      esac
      # Resolve the name on the HOST, against the image's own
      # /etc/passwd, never by asking the running image (review I-3): an
      # untrusted image can ship a spoofed `id`. `docker cp` reads the
      # file off the image's filesystem without starting it.
      passwd_table=""
      if docker create --name uidprobe app-under-test >/dev/null 2>&1; then
        passwd_table="$(docker cp uidprobe:/etc/passwd - 2>/dev/null | tar -xO 2>/dev/null | tr '\000' '\001' || true)"
      fi
      docker rm -f uidprobe >/dev/null 2>&1 || true
      if [ -z "$passwd_table" ]; then
        refuse "cannot be resolved: the image has no readable /etc/passwd, refusing (fail closed)"
      fi
      # The name reaches awk through ENVIRON, never -v (which expands
      # backslash escapes). `loose` counts lines whose name matches
      # after trimming every leading and trailing byte outside
      # printable ASCII, a superset of the whitespace Docker trims;
      # `exact` counts lines whose untrimmed first field matches. Both
      # compares append "" to force a STRING compare: awk compares
      # numerically when both sides look numeric, so 1e3 would match a
      # passwd name 1000.
      uid="$(printf '%s\n' "$passwd_table" | U="$user_part" LC_ALL=C awk -F: '
        {
          line = $0
          sub(/^[^!-~]+/, "", line)
          sub(/[^!-~]+$/, "", line)
          split(line, f, ":")
          if ((f[1] "") == (ENVIRON["U"] "")) loose++
          if (($1 "") == (ENVIRON["U"] "")) { exact++; field = $3 }
        }
        END {
          if (loose == 0 && exact == 0) print "none"
          else if (loose != 1 || exact != 1) print "ambiguous"
          else if (field !~ /^[0-9]+$/) print "malformed"
          else print field
        }')"
      case "$uid" in
        none)
          refuse "does not match any /etc/passwd entry, refusing (fail closed)" ;;
        ambiguous)
          refuse "matches /etc/passwd ambiguously (on more than one line, or on a line with leading blanks, or with blanks inside the name field), refusing (fail closed)" ;;
        malformed)
          refuse "matches an /etc/passwd line whose uid field is not a plain number, refusing (fail closed)" ;;
      esac
      ;;
    *)
      uid="$user_part"
      ;;
  esac
  # $uid is plain digits here. Strip leading zeros as TEXT (Docker
  # reads 00 and 0000 as 0) and check the length before any numeric
  # compare, so a huge value can never wrap in the shell.
  uid_norm="$(printf '%s' "$uid" | sed 's/^0*//')"
  if [ -z "$uid_norm" ]; then
    refuse "resolves to uid 0, refusing"
  fi
  if [ "${#uid_norm}" -gt 10 ] || [ "$uid_norm" -gt 2147483647 ]; then
    refuse "resolves to uid $uid, outside 1 to 2147483647, refusing"
  fi
  echo "container-validate: runs as non-root user '$shown' (uid $uid_norm)"

  ports="$(docker inspect --format='{{json .Config.ExposedPorts}}' app-under-test)"
  # A here-string, not a pipe: under pipefail a grep -q that matched and
  # exited before echo finished writing would fail the pipeline.
  if ! grep -q '"8080/tcp"' <<<"$ports"; then
    # The image's config writes these keys, so the plain line shows
    # them as it shows Config.User above; the helper's logSafe
    # flattens its own copy.
    shown_ports="$(printf '%s' "$ports" | LC_ALL=C tr -c ' -~' '?' | sed 's/##\[/## [/g')"
    echo "container-validate: image does not EXPOSE 8080 (ExposedPorts=$shown_ports), refusing" >&2
    node "$ci/annotate.mjs" --title "Container contract" --file Dockerfile \
      --what "the image does not EXPOSE 8080 (ExposedPorts=$ports)" \
      --fix "add EXPOSE 8080 and listen on port 8080"
    exit 1
  fi
  echo "container-validate: exposes 8080"
}

# Contract R2 made real at build time: the container must come up and answer
# GET /healthz with exactly 200, the same test the runtime health probe
# applies (the step's comment in platform-ci.yml says why, and how long).
healthz() {
  docker run -d --name smoke -p 8080:8080 app-under-test
  ok=""
  last=""
  exited=""
  for _ in $(seq 1 18); do
    last="$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://localhost:8080/healthz || true)"
    if [ "$last" = "200" ]; then ok=1; break; fi
    # A container that has already exited is never going to answer, so
    # a crash on start costs one try and its logs instead of the whole
    # window. `|| echo false` keeps a vanished container from ending
    # the step under errexit before the logs below are printed.
    if [ "$(docker inspect -f '{{.State.Running}}' smoke 2>/dev/null || echo false)" != "true" ]; then exited=1; break; fi
    sleep 5
  done
  if [ -z "$ok" ]; then
    if [ -n "$exited" ]; then
      said="container-validate: the container exited before /healthz answered 200, last status: ${last:-none}; refusing"
    else
      said="container-validate: /healthz did not answer 200 within 18 tries (about 90s when the port refuses, about 162s when it accepts and hangs), last status: ${last:-none}; refusing"
    fi
    # The sentence, then its annotation (R7-5), then the container's
    # own output, which is the evidence.
    echo "$said" >&2
    node "$ci/annotate.mjs" --title "Container contract" --what "$said" \
      --fix "serve GET /healthz with a 200 on port 8080 within about 90 seconds of start; the step log ends with the container's own output"
    echo "--- container logs ---" >&2
    docker logs smoke >&2 || true
    docker rm -f smoke || true
    exit 1
  fi
  echo "container-validate: /healthz healthy"
  docker rm -f smoke
}

case "$#:${1:-}" in
  1:user) user ;;
  1:healthz) healthz ;;
  *) echo "usage: container-contract.sh <user|healthz>" >&2; exit 2 ;;
esac
