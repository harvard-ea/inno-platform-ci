#!/usr/bin/env bash
# Mint a short-lived GitHub Actions OIDC token for the given audience, via the
# raw ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN request the runner serves: the one
# way every workflow here mints one, and from v0.18.16 the one place a token
# is masked. The platform's own workflows mint through their scripts:
# ci/broker-manifest.sh (the safety sweep's and the data export's manifest
# fetch), ci/sweep-lane.sh and ci/export-archives.sh (once per app or archive,
# inside their loops, since one item's work can outlast a token's TTL) and
# ci/release-hosts.sh (the deploy's host wave). Tenant CI (platform-ci.yml)
# mints in each step that sends a token, from the mirror's copy of this
# script, which the mirror publishes (v0.18.16, CI-03: every job that mints one
# checks the mirror out, the policy job included).
#
# The request is bounded at 30 s and retried twice (it is a read, so a retry
# costs one more request), so a hung token service fails the step instead of
# holding the job to its timeout. Each broker curl in the calling workflows
# states its own bound beside it.
#
# Usage: token="$(ci/oidc-token.sh <audience>)"
# Requires: `permissions: id-token: write` on the calling job (which sets
# ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN in the environment).
set -euo pipefail

audience="${1:?usage: oidc-token.sh <audience>}"

if [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] || [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
  echo "oidc-token.sh: ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN are not set. Does this job have 'permissions: id-token: write'?" >&2
  exit 1
fi

resp="$(curl -sS --max-time 30 --retry 2 -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$audience")"
token="$(printf '%s' "$resp" | jq -r '.value // empty')"

if [ -z "$token" ]; then
  echo "oidc-token.sh: no .value in the OIDC token response: $resp" >&2
  exit 1
fi

# Masked first, on stderr, which the runner reads workflow commands from as
# it reads stdout: the job's log then hides the token wherever a later
# command would print it, in every workflow that mints one here. stdout
# stays the token alone, for the caller's $(...).
echo "::add-mask::$token" >&2
printf '%s' "$token"
