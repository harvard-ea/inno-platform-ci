#!/usr/bin/env bash
# The Dockerfile misconfiguration REPORT for tenant CI's container job
# (contract 22, R8), the step "Dockerfile misconfiguration report (trivy
# config, report only)", run from the job's mirror checkout: `trivy config`
# over a copy of the app's Dockerfile, with the workflow's one trivy image
# ($TRIVY_IMAGE) and the job's token for its checks bundle ($TRIVY_TOKEN).
# Report-only in every mode, so it never exits non-zero: every command that
# can fail carries its own `||` and exit 0, and
# test/a11y-workflow.node.test.ts plants a failure in each. (The step's
# inline body until v0.18.16, CI-02.)
#
# Usage: ci/dockerfile-report.sh, from the app checkout's root, with
# TRIVY_IMAGE and TRIVY_TOKEN in the environment.
set -euo pipefail
# $TRIVY_IMAGE is the workflow's one trivy digest, the trivy gate's
# (the digest-parity lint holds it to the sweep's). NOTE: keep comments
# ABOVE `docker run`, never between its backslash-continued lines.
if [ ! -f Dockerfile ] || [ -L Dockerfile ]; then
  echo "::warning title=Dockerfile report::no regular Dockerfile at the repo root; nothing to report" >&2
  exit 0
fi
D="$RUNNER_TEMP/dockerfile-report"
{ mkdir -p "$D/src" && cp Dockerfile "$D/src/Dockerfile"; } || { echo "::warning title=Dockerfile report::could not stage the Dockerfile; not blocking" >&2; exit 0; }
timeout -k 10 180 docker run --rm \
  -v "$HOME/.cache/trivy:/root/.cache/trivy" \
  -v "$D/src:/src:ro" \
  -e GITHUB_TOKEN="$TRIVY_TOKEN" \
  "$TRIVY_IMAGE" config \
    --severity HIGH,CRITICAL \
    --exit-code 0 \
    --quiet \
    --format json \
    /src > "$D/report.json" \
  || { echo "::warning title=Dockerfile report::trivy config did not complete; report only, not blocking" >&2; exit 0; }
# Finding text quotes the app's Dockerfile, so it is app-controlled:
# control characters are flattened (no forged workflow command),
# table text is entity-encoded except letters, digits and inert
# punctuation (no table break, HTML, link, image, emphasis or
# autolink; "." is encoded too, since GitHub autolinks a bare
# www.example.com/x), and annotation titles escape the property
# separators.
# shellcheck disable=SC2016 # jq programs, not shell expansions
JQDEFS='
  def flat: gsub("[[:cntrl:]]+"; " ");
  def enc: flat | explode | map(
    if (. >= 48 and . <= 57) or (. >= 65 and . <= 90) or (. >= 97 and . <= 122)
      or . == 32 or . == 44 or . == 45 or . == 47 or . == 59 or . == 61 or . == 63
    then [.] | implode else "&#\(.);" end) | join("");
  def prop: flat | gsub("%"; "%25") | gsub(":"; "%3A") | gsub(","; "%2C");
  def findings: [.Results[]?.Misconfigurations[]?];
'
n="$(jq -r "$JQDEFS"' findings | length' "$D/report.json" 2>/dev/null || echo "?")"
{
  echo "### Dockerfile misconfiguration report (trivy config, HIGH/CRITICAL, report only)"
  echo ""
  if [ "$n" = "0" ]; then
    echo "No HIGH or CRITICAL findings."
  else
    echo "| Check | Severity | Finding |"
    echo "|---|---|---|"
    jq -r "$JQDEFS"' findings | (.[:50][] | "| \(.ID // "?" | .[:40] | enc) | \(.Severity // "?" | .[:20] | enc) | \(((.Title // "") + ": " + (.Message // "")) | .[:300] | enc) |"), (length - 50 | select(. > 0) | "", "\(.) more finding(s) not listed here.")' "$D/report.json" 2>/dev/null || true
  fi
} >> "$GITHUB_STEP_SUMMARY" || true
# 10 warnings is GitHub's cap per kind per step, and nothing else in
# this step warns once trivy has run; the rest are counted in a
# notice, which no finding can crowd out. On stderr, as every
# annotation is (OPEN 149): the >&2 comes before the 2>/dev/null
# that drops jq's own errors, or it would drop the lines too.
jq -r "$JQDEFS"' findings | (.[:10][] | "::warning title=Dockerfile (\(.Severity // "?" | .[:20] | prop)) \(.ID // "?" | .[:40] | prop)::\(((.Title // "") + ": " + (.Message // "")) | .[:300] | flat | gsub("%"; "%25"))"), (length - 10 | select(. > 0) | "::notice title=Dockerfile report::\(.) more finding(s) (first 50 in the step summary)")' "$D/report.json" >&2 2>/dev/null || true
echo "dockerfile-report: $n HIGH/CRITICAL finding(s); report only"
