#!/usr/bin/env bash
# The deps job's npm audit gate for tenant CI, the step "npm audit
# (app/package.json, if present)", which runs it from its mirror checkout:
# an audit of the app author's own dependencies in app/package.json, read
# from the lockfile without installing (the step's comment in platform-ci.yml
# says why the gate exists and what it refuses). A function app with
# app/package.json and no committed lockfile is refused with app-build's own
# sentence; a container app's throwaway lockfile is resolved and audited.
# The verdict is ci/sweep-results.mjs gate's, beside this script, so
# safety.ignore.deps.* (IGNORES) applies to npm as it does to pip-audit.
# (The step's inline body until v0.18.16, CI-02.)
#
# Usage: ci/app-npm-audit.sh, from the app checkout's root, with
# FUNCTION_SHAPED and IGNORES in the environment; any argument exits 2.
set -euo pipefail
ci="$(cd "${0%/*}" && pwd -P)"
if [ "$#" -ne 0 ]; then
  echo "usage: app-npm-audit.sh" >&2
  exit 2
fi
if [ -f app/package.json ]; then
  cd app
  if [ ! -f package-lock.json ]; then
    if [ "$FUNCTION_SHAPED" = "true" ]; then
      echo "::error title=Missing app/package-lock.json::commit app/package-lock.json; the platform deploys the versions the dependency gates audited, and will not resolve your ranges fresh at deploy time" >&2
      exit 1
    fi
    # A container app's throwaway resolution. Do NOT swallow this: an
    # unresolvable app/package.json means the gate has nothing to
    # audit, which must fail loudly rather than silently pass. (A gate
    # that only logs a warning is a broken gate.)
    npm install --package-lock-only --ignore-scripts || {
      echo "::error title=Dependency gate::could not resolve app/package.json into a lockfile: fix the dependency ranges or commit a package-lock.json" >&2
      exit 1
    }
  fi
  # npm exits 1 on findings; the filter script is the gate's verdict.
  npm audit --package-lock-only --omit=dev --audit-level=high --json > audit.json || true
  node "$ci/sweep-results.mjs" gate audit.json
else
  echo "no app/package.json, skipping app npm audit"
fi
