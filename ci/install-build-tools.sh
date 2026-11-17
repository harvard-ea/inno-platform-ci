#!/usr/bin/env bash
# The platform's build tools for tenant CI: the wrangler the mirror's
# ci/build/ lockfile pins (with the esbuild and Tailwind CLI ci/build-ui.mjs
# runs), which follows the mirror's main (PLATFORM_REF) as the ci/ scripts
# do. Installed, install scripts off, in a copy under $RUNNER_TEMP outside the
# app checkout, so nothing of the author's sits on its resolution path, and
# exported to the job's later steps as $WRANGLER. wrangler runs exclusively
# as "$WRANGLER", never via `npx` (which would fetch it from the registry,
# unpinned).
#
# Two jobs run it from their mirror checkout (each pasted its own copy until
# v0.18.16, CI-02): app-build, with --bundle-config, which also puts the
# mirror's bundling config and compiler settings at the checkout root over
# any author file of either name (app-worker.jsonc, which names the entry
# and the compatibility values and nothing else, and tsconfig.json, a real
# build input of the app Worker; the step's comment says why), and the deploy
# job, for a container app's image push.
#
# Usage: install-build-tools.sh [--bundle-config]; any other argument exits 2.
set -euo pipefail
ci="$(cd "${0%/*}" && pwd -P)"
bundle_config=false
if [ "$#" -eq 1 ] && [ "$1" = --bundle-config ]; then
  bundle_config=true
elif [ "$#" -ne 0 ]; then
  echo "usage: install-build-tools.sh [--bundle-config]" >&2
  exit 2
fi

# A directory an earlier attempt left on the runner is removed first, so
# nothing stale rides into the install.
rm -rf "$RUNNER_TEMP/build-tools"
cp -R "$ci/build" "$RUNNER_TEMP/build-tools"
(cd "$RUNNER_TEMP/build-tools" && npm ci --ignore-scripts)
echo "WRANGLER=$RUNNER_TEMP/build-tools/node_modules/.bin/wrangler" >> "$GITHUB_ENV"
if [ "$bundle_config" = true ]; then
  # Removed first: `cp` onto a committed symlink of either name
  # would write the mirror's file through it, wherever it points.
  rm -f app-worker.jsonc tsconfig.json
  cp "$ci/app-worker.jsonc" app-worker.jsonc
  cp "$ci/tsconfig.app.json" tsconfig.json
fi
