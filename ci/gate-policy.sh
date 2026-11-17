#!/usr/bin/env bash
# The policy job's fetch, for tenant CI (platform-ci.yml's "Fetch gate
# policy" step, which runs it from its mirror checkout): asks the broker's
# /ci/policy for this app's effective gate policy and writes it to the step's
# outputs, one plain string each, so every gate job tests its own toggle and
# ignore list without parsing JSON, and all of the policy's jq stays here.
#
# A refusal fails the job; an outage never does (R7-4). A refusal is an
# answer whose status is a 4xx other than 401 and 429 and whose body is the
# broker's JSON with a string `error` (app_mismatch, repo_unlinked, a
# provenance pin): /deploy-token refuses the same app, so running the gates
# on a guessed policy would only move the failure somewhere it says less (a
# function app's doomed docker build). Anything else, no answer, a 5xx, a 401
# (the platform could not verify this run's token, which a fault of its own,
# a JWKS or issuer read, answers too; a release still fails closed at
# /deploy-token's same 401), a 429 (a brake is an outage, not a verdict on the
# app), any other status or a body that is not the broker's, must not block a
# deploy, and falls back to the SECURE direction (everything on) (build
# decision 16).
#
# The refusal prints through ci/annotate.mjs beside this script, the one
# annotation rule (ci/cli.mjs annotationLine), from the body's `error` and
# `message` read by two plain jq lines (v0.18.16, CI-04: until then this job
# had no mirror checkout, and a jq program restated the rule for it).
#
# Usage: ci/gate-policy.sh, with BROKER_URL, OIDC_TOKEN and APP in the
# environment, as the step's own env and the workflow's give them; it writes
# $GITHUB_OUTPUT, and the body to $RUNNER_TEMP/policy.json.
set -euo pipefail
ci="$(cd "${0%/*}" && pwd -P)"
body="$RUNNER_TEMP/policy.json"
NO_REASON="the platform gave no reason; a platform admin can find it in the platform's audit log (its deploy_denied rows) or its Worker log"

emit_defaults() {
  echo "::warning title=Gate policy unavailable::running all gates with no ignores (secure default)" >&2
  for g in semgrep trivy gitleaks deps; do echo "gates_$g=true" >> "$GITHUB_OUTPUT"; done
  for t in semgrep trivy deps; do echo "ignores_$t=" >> "$GITHUB_OUTPUT"; done
  # Falls back to function_shaped=false and perimeter=sso on a
  # broker outage: the safe, original build path (a function app
  # that can't be identified just runs the container gates, which
  # its repo won't satisfy, and fails safely).
  echo "perimeter=sso" >> "$GITHUB_OUTPUT"
  echo "function_shaped=false" >> "$GITHUB_OUTPUT"
  # Cooldown has no "secure default" that could block a legit deploy on
  # a broker outage (a length-of-time gate isn't a safety scanner), so
  # it fails OPEN to 0 (off), consistent with never blocking on the
  # broker being down.
  echo "min_release_age_days=0" >> "$GITHUB_OUTPUT"
  # The accessibility check falls back to REPORT (never enforce, never
  # off): a broker outage must neither start blocking deploys on a
  # quality check nor silently drop the report.
  echo "a11y_mode=report" >> "$GITHUB_OUTPUT"
  echo "ignores_a11y=" >> "$GITHUB_OUTPUT"
  # The scan falls back to identity-aware (a synthetic member), the
  # headers every app was scanned with before identity existed.
  echo "identity=identity-aware" >> "$GITHUB_OUTPUT"
}

# The body goes to a file and the status to stdout, so the two are
# judged apart; the file is emptied first, so a body curl never
# wrote reads as none.
: > "$body"
code="$(curl -sS -o "$body" -w '%{http_code}' --max-time 15 --retry 2 -X POST "$BROKER_URL/ci/policy" \
  -H "Authorization: Bearer $OIDC_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"app\":\"$APP\"}")" || { emit_defaults; exit 0; }
case "$code" in
  200) ;;
  401|429) emit_defaults; exit 0 ;;
  4??)
    # jq -e passes one JSON object with a string `error` (an empty one
    # included) and nothing else: a body that is not JSON, holds more than
    # one value or no string error reads as an outage. NUL bytes become
    # \001 before they reach a shell variable, which would drop them; both
    # are control bytes, which annotate.mjs flattens alike.
    if error="$(jq -ers 'if length == 1 and (.[0] | type) == "object" and (.[0].error | type) == "string" then .[0].error else null end' "$body" 2>/dev/null | tr '\000' '\001')"; then
      fix="$(jq -rs --arg none "$NO_REASON" '.[0].message | if type == "string" then . else $none end' "$body" | tr '\000' '\001')"
      node "$ci/annotate.mjs" --title="Platform refused this app" \
        --what="the platform refused this repository's CI for app \"$APP\" ($error)" --fix="$fix"
      exit 1
    fi
    emit_defaults; exit 0 ;;
  *) emit_defaults; exit 0 ;;
esac
resp="$(cat "$body")"
if ! printf '%s' "$resp" | jq -e '.gates | type == "object"' >/dev/null 2>&1; then
  emit_defaults
  exit 0
fi
# Partial policy resolves SECURE: a missing gate key reads true, a
# missing ignores list reads empty. IDs are grammar-filtered here (a
# third layer after write-time + serve-time validation) because they
# get word-split into tool flags in the gate jobs.
for g in semgrep trivy gitleaks deps; do
  echo "gates_$g=$(printf '%s' "$resp" | jq -r --arg g "$g" '.gates[$g] != false')" >> "$GITHUB_OUTPUT"
done
for t in semgrep trivy deps a11y; do
  echo "ignores_$t=$(printf '%s' "$resp" | jq -r --arg t "$t" '(.ignores[$t] // []) | map(select(test("^[A-Za-z0-9][A-Za-z0-9._-]*$"))) | join(" ")')" >> "$GITHUB_OUTPUT"
done
# A missing or unknown mode reads as report (the non-blocking default).
echo "a11y_mode=$(printf '%s' "$resp" | jq -r 'if (.a11y_mode == "off" or .a11y_mode == "enforce") then .a11y_mode else "report" end')" >> "$GITHUB_OUTPUT"
# Only the broker's "anonymous" reads anonymous; a missing or
# unknown identity reads identity-aware, as on an outage.
echo "identity=$(printf '%s' "$resp" | jq -r 'if .identity == "anonymous" then "anonymous" else "identity-aware" end')" >> "$GITHUB_OUTPUT"
# Numeric cooldown threshold; a missing/garbage value reads 0 (off).
echo "min_release_age_days=$(printf '%s' "$resp" | jq -r '(.min_release_age_days // 0) | if type=="number" then . else 0 end')" >> "$GITHUB_OUTPUT"
# Axes only (the legacy type field died with Phase B); unknown/absent
# values fail safe to the container x sso path exactly as before.
shape="$(printf '%s' "$resp" | jq -r 'if .shape == "function" then "function" else "container" end')"
perimeter="$(printf '%s' "$resp" | jq -r 'if .perimeter == "oauth-rs" then "oauth-rs" else "sso" end')"
echo "perimeter=$perimeter" >> "$GITHUB_OUTPUT"
# The shape axis reaches the gates as one flag, function_shaped,
# which every condition reads.
if [ "$shape" = "function" ]; then
  echo "function_shaped=true" >> "$GITHUB_OUTPUT"
else
  echo "function_shaped=false" >> "$GITHUB_OUTPUT"
fi
