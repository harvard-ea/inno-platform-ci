#!/usr/bin/env bash
# The accessibility + response-header REPORT for tenant CI's container job
# (contract 22, R8, section 3; docs/APP-ACCESSIBILITY.md), the step
# "Accessibility + response-header report (axe-core; safety.a11y.mode)", run
# from the job's mirror checkout after the build, against the image the smoke
# test ran (app-under-test). Its verdict is policy-defined (the workflow's
# header and the step's comment say how): it exits 1 in exactly one case, the
# mode is enforce, the scanner exited 1 and the scanner's own result.json
# confirms that verdict, and every failure on the platform's side warns and
# exits 0, in every mode.
#
# It runs under set -euo pipefail, so a command left unguarded would fail
# every tenant deploy on a platform hiccup: each one that can fail carries its
# own `||`, and test/a11y-workflow.node.test.ts plants a failure in every one.
# pipefail is what hands a failed openssl in the integrity pipeline to its
# `||` rather than base64's 0. It finds its own directory with shell builtins
# alone, for the same reason. There is no step timeout-minutes either: each
# slow command has its own `timeout`, whose sum is worked out above the
# scanner's run. (The step's inline body until v0.18.16, CI-02.)
#
# Usage: ci/a11y-report.sh, with A11Y_MODE, A11Y_IGNORES, APP and IDENTITY in
# the environment, as the step's env gives them, and the step's three pins:
# SCANNER_IMAGE (the scanner image, by digest), AXE_VERSION and AXE_INTEGRITY
# (axe-core's version and its published npm sha512 integrity), which stay in
# the workflow's YAML, where a reader of the workflow finds them.
set -euo pipefail
ci="$(cd "${0%/*}" && pwd -P)"
case "$A11Y_MODE" in off|report|enforce) ;; *) A11Y_MODE=report ;; esac
if [ "$A11Y_MODE" = "off" ]; then
  echo "::warning title=Accessibility check off::safety.a11y.mode is off for this app; no accessibility scan ran" >&2
  echo "### :warning: Accessibility check OFF by platform policy (safety.a11y.mode)" >> "$GITHUB_STEP_SUMMARY" || true
  exit 0
fi
NET="inno-a11y-${GITHUB_RUN_ID:-0}-${GITHUB_RUN_ATTEMPT:-0}"
APPC="a11y-app-${GITHUB_RUN_ID:-0}-${GITHUB_RUN_ATTEMPT:-0}"
SCANC="a11y-scan-${GITHUB_RUN_ID:-0}-${GITHUB_RUN_ATTEMPT:-0}"
# Every failure before the scanner's own verdict is platform-side:
# loud, never blocking, in either mode.
not_run() {
  echo "::warning title=Accessibility scan did not run::$1; this is not a clean result (platform-side; not blocking)" >&2
  echo "### :warning: Accessibility scan did not run: $1" >> "$GITHUB_STEP_SUMMARY" || true
  exit 0
}
# The scanner is this script's sibling in the mirror's ci/
# (scripts/publish-mirror.sh); that directory is mounted below as /ci.
if [ ! -f "$ci/a11y-scan.mjs" ]; then not_run "ci/a11y-scan.mjs is missing from the platform's CI mirror"; fi
SCAN="$RUNNER_TEMP/a11y"
{ rm -rf "$SCAN" && mkdir -p "$SCAN/out" "$SCAN/in"; } || not_run "could not create the scan directory"
curl -fsSL --max-time 30 --retry 1 -o "$SCAN/axe.tgz" "https://registry.npmjs.org/axe-core/-/axe-core-$AXE_VERSION.tgz" \
  || not_run "could not download axe-core $AXE_VERSION"
got="sha512-$(openssl dgst -sha512 -binary "$SCAN/axe.tgz" | base64 -w0)" || got=""
if [ "$got" != "$AXE_INTEGRITY" ]; then not_run "axe-core $AXE_VERSION failed its integrity check"; fi
tar -xzf "$SCAN/axe.tgz" -C "$SCAN" package/axe.min.js || not_run "could not unpack axe-core"
mv "$SCAN/package/axe.min.js" "$SCAN/in/axe.min.js" || not_run "could not stage axe-core"
# The app's optional route list: a regular file (not a symlink) up to
# 64 KB, copied in; the scanner validates its contents.
if [ -L app/inno-a11y.json ]; then
  echo "::warning title=Accessibility routes::app/inno-a11y.json is a symlink, which is never followed; scanned / only" >&2
elif [ -f app/inno-a11y.json ]; then
  size="$(wc -c < app/inno-a11y.json 2>/dev/null || echo 0)"
  if [ "$size" -le 65536 ]; then
    cp app/inno-a11y.json "$SCAN/in/routes.json" || true
  else
    echo "::warning title=Accessibility routes::app/inno-a11y.json is over 64 KB; scanned / only" >&2
  fi
fi
{ chmod -R a+rX "$SCAN/in" && chmod a+rwx "$SCAN/out"; } || not_run "could not prepare the scan directory"
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  timeout 20 docker rm -f "$SCANC" >/dev/null 2>&1 || true
  timeout 20 docker rm -f "$APPC" >/dev/null 2>&1 || true
  timeout 20 docker network rm "$NET" >/dev/null 2>&1 || true
  # The scanner image is about 2 GB unpacked; on a tag run the next
  # step docker-saves the app image to the same runner disk.
  timeout 60 docker image rm "$SCANNER_IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT
# Pulled on its own clock so the scan's timeout below measures only
# the scan (the image is large, about 2 GB unpacked).
timeout 240 docker pull -q "$SCANNER_IMAGE" >/dev/null || not_run "could not pull the scanner image"
timeout 30 docker network create "$NET" >/dev/null || not_run "could not create the scan network"
# The alias must not be a public suffix: Chromium HSTS-preloads TLDs
# such as .app and .dev, so http://app:8080 is silently upgraded to
# https and never loads. a11y-target is not a TLD.
timeout 60 docker run -d --name "$APPC" --network "$NET" --network-alias a11y-target app-under-test >/dev/null \
  || not_run "could not start the app image for the scan"
# The scan boots a FRESH container of the image, so its /healthz wait
# is the smoke test's own window (about 90 s), not a shorter one that
# would report a slow boot as "did not run". The hard ceiling covers
# that 90 s, the scanner's 5-minute budget and 60 s for Chromium's
# start and the last page's overrun; a kill (124/137) is
# platform-side, below. Worst case for the whole step, which has no
# timeout-minutes: 60 s download + 240 s pull + 90 s docker setup +
# 460 s scan (450 plus the kill grace) + 120 s cleanup (three 20 s
# removals and the 60 s image removal) = 970 s, about 16 minutes,
# the share of the container job's timeout budgeted for it.
status=0
timeout -k 10 450 docker run --rm --init --name "$SCANC" --network "$NET" \
  --user pwuser --cap-drop ALL --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:rw,size=512m --pids-limit 512 --memory 2g \
  -v "$ci:/ci:ro" \
  -v "$SCAN/in:/in:ro" \
  -v "$SCAN/out:/out" \
  "$SCANNER_IMAGE" \
  node /ci/a11y-scan.mjs --base http://a11y-target:8080 --axe /in/axe.min.js \
    --app "$APP" --identity "$IDENTITY" --mode "$A11Y_MODE" --ignore "$A11Y_IGNORES" --routes /in/routes.json \
    --summary /out/summary.md --json /out/result.json --wait-healthz 90 || status=$?
# The scanner's outputs are read only as regular files: /out is the
# one directory the scanner container can write, so a symlink there
# is refused (never followed into the runner's filesystem).
if [ -L "$SCAN/out/summary.md" ]; then
  echo "::warning title=Accessibility report::the scanner's summary is a symlink and was not read (platform-side; not blocking)" >&2
elif [ -f "$SCAN/out/summary.md" ]; then
  head -c 200000 "$SCAN/out/summary.md" >> "$GITHUB_STEP_SUMMARY" || true
fi
RESULT="$SCAN/out/result.json"
case "$status" in
  0) ;;
  1)
    # Exit 1 is also what any Node crash returns, so it blocks only
    # in enforce mode, and only when the scanner's own result file
    # confirms an app verdict. A missing jq, an unreadable file or a
    # symlink all leave it unconfirmed: platform-side, not blocking.
    if [ "$A11Y_MODE" = "enforce" ] && [ -f "$RESULT" ] && [ ! -L "$RESULT" ] \
      && jq -e '.outcome.exitCode == 1 and .mode == "enforce"' "$RESULT" >/dev/null 2>&1; then
      echo "::error title=Accessibility check failed::safety.a11y.mode is enforce for this app; fix what the accessibility report above marks as blocking (critical/serious findings, or a landing page that could not be scanned), or ask a platform admin to waive a rule (safety.ignore.a11y.<rule>)" >&2
      exit 1
    fi
    echo "::warning title=Accessibility scanner error::the scanner exited 1 without a confirmed verdict (platform-side); not blocking" >&2 ;;
  *)
    echo "::warning title=Accessibility scanner error::the scanner exited $status (platform-side); not blocking" >&2 ;;
esac
exit 0
