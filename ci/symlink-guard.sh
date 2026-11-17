#!/usr/bin/env bash
# The symlink guard of tenant CI's app-build and container jobs (each job's
# step "Reject a symlink that escapes the repository" runs it, app-build from
# its mirror checkout and the container job from its $RUNNER_TEMP/ci copy): it
# refuses any symlink in the checkout whose target resolves outside the
# repository checkout ($GITHUB_WORKSPACE), and any dangling one, walking the
# whole checkout from the step's working directory, node_modules included,
# and pruning .git and the mirror checkout (public platform code). Only a
# directory at the mirror checkout's path is pruned: a link of that name is
# walked and refused like any other (v0.18.31, ruling R15). The step's
# comment in platform-ci.yml says why, and what it does not contain.
#
# Each refused link is one annotation from ci/annotate.mjs beside this
# script, the link as its file, so a link's name, which the author (or a
# dependency's tarball) chose, reaches the log only through logSafe. GitHub
# keeps ten annotations of a kind a step, so links past the tenth are named in
# one plain line instead, each name through the same logSafe (build decision
# 14). A name can start with "-" (a link at the checkout root reaches each
# command bare), so realpath takes it after --, every helper argument is
# --opt=value, and the plain line's names follow the helper's path after --
# (build decision 16). (The step's inline body until v0.18.16, CI-02.)
#
# Usage: ci/symlink-guard.sh, from the checkout root, with GITHUB_WORKSPACE
# set.
set -euo pipefail
ci="$(cd "${0%/*}" && pwd -P)"
root="$(cd "$GITHUB_WORKSPACE" && pwd -P)"
bad=0
more=()
refuse_link() {
  bad=$((bad + 1))
  if [ "$bad" -le 10 ]; then
    node "$ci/annotate.mjs" --title="$1" --file="$2" --what="$3" --fix="$4"
  else
    more+=("$2")
  fi
}
while IFS= read -r -d '' link; do
  link="${link#./}"
  # `-e` follows the link, so a dangling one (its target, or a link
  # in its chain, missing) fails here on every runner: GNU realpath
  # prints a path for a missing final component where BSD's does not.
  if [ -e "$link" ] && tgt="$(realpath -- "$link" 2>/dev/null)"; then
    case "$tgt/" in
      "$root"/*) : ;;
      *) refuse_link "Symlink escapes the repository" "$link" "$link resolves outside your repository (-> $tgt)" "replace it with the file it points to, or remove it" ;;
    esac
  else
    refuse_link "Dangling symlink" "$link" "$link does not resolve" "remove it"
  fi
done < <(find . \( -path ./.git -o -path ./inno-platform-ci -type d \) -prune -o -type l -print0)
if [ "${#more[@]}" -gt 0 ]; then
  # shellcheck disable=SC2016 # a JavaScript template, not a shell expansion
  node --input-type=module -e 'const { logSafe } = await import(process.argv[1]); const names = process.argv.slice(2); console.error(`and ${names.length} more symlinks: ${names.map((n) => logSafe(n, 300)).join(", ")}`);' -- "$ci/cli.mjs" "${more[@]}"
fi
if [ "$bad" -ne 0 ]; then
  echo "A symlink in your repository points outside it; a link may name only a file inside your repository. Remove it, or point it inside." >&2
  exit 1
fi
