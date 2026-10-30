#!/usr/bin/env node
// Config-integrity gate: verifies an app repo has not weakened the security
// posture the platform requires: required CLAUDE.md guidance present, no
// platform-owned build input vendored into the app repo (the root build
// files and ANY wrangler config; the platform supplies them at build time
// from its mirror), nothing of the author's under src/ (which the platform
// owns), and no package-manager configuration at any depth (npm expands
// ${VAR} from the environment into it). The live checks are 1, 1b, 1c, 6, 6b,
// 7, 7b and 8; see checkConfig's own note on the numbering.
//
// Usage: node ci/check-config.mjs <app-dir>
// Exits 0 if compliant, 1 (with violations printed) otherwise.
//
// Zero npm dependencies: node:fs, node:path builtins plus the local (also
// zero-dependency) ci/cli.mjs helper only.

import { existsSync, lstatSync, readFileSync, readdirSync, readlinkSync, realpathSync, statSync } from "node:fs";
import { join, sep } from "node:path";
import { annotateAll, isMainModule, logSafe } from "./cli.mjs";

// Headers every app's CLAUDE.md must carry, regardless of deployment type.
const REQUIRED_CLAUDE_MD_HEADERS = [
  "## Innovation Platform App",
  "## Identity (do not build auth)",
  "## What CI enforces",
];

// Type-variant header groups: each group carries the same safety guidance for
// its runtime, and ANY member satisfies the gate. The gate stays
// deliberately type-blind: it must not depend on the broker's policy fetch
// (which can fall back to 'container' on an outage) to know which variant to
// demand, and pre-scaffold apps all carry the container member. The retired
// "## Worker contract" heading (the 'function' preset's before 2026-07-30) is
// no longer accepted (v0.17.3): an app still carrying it renames it.
const CLAUDE_MD_HEADER_VARIANTS = [
  ["## Persistence (use the storage client)", "## Persistence (use your bindings)"],
  ["## Container contract", "## Function contract"],
];

// Worker build-input files that are platform-owned: the app-build job's
// wrangler runs with the checkout root as its cwd, that job copies the
// mirror's tsconfig there for the function-shaped app Worker's tsconfig
// lookup (an author's app/tsconfig.json, which R7 permits, is found first),
// and an author package.json or lockfile there would sit in the bundler's
// lookup from app/index.ts. A vendored copy would shadow them and is always stale, so
// check 8 rejects any of them outright. They are not template files any more;
// .github/workflows/ci.yml's template-drift reverse walk says so too.
const PINNED_BUILD_INPUT_FILES = ["package.json", "package-lock.json", "tsconfig.json"];

// wrangler discovers its config in the app root as `wrangler.json ??
// wrangler.jsonc ?? wrangler.toml`, honoring env-variants too. The platform
// supplies the ONLY permitted config (a function app's app-worker.jsonc, from
// the mirror, which the app-build job bundles with; a container app has no
// Worker config of its own), so ANY wrangler config committed to an app repo
// is a shadow or a bypass and is rejected. `--config app-worker.jsonc` in
// app-build's bundle step pins the file as the belt to this suspenders.
// Matches a wrangler config file we must reject: the bare `wrangler.json` /
// `wrangler.toml`, or any env-variant `wrangler.<something>.(json|jsonc|toml)`.
// wrangler.jsonc itself never matches (no middle segment, and .jsonc is only
// reached via the env-variant arm which requires a `.<env>.` in between).
const COMPETING_WRANGLER_RE = /^wrangler\.(json|toml|.+\.(json|jsonc|toml))$/;

// Every package manager's project-level configuration, rejected at the repo
// ROOT: wrangler runs with the checkout root as its cwd (no root install
// happens: the build tools install in a platform-owned directory outside the
// checkout), and a .pnpmfile.cjs is arbitrary JavaScript an install would
// execute. At depth only .npmrc matters (check 6b): npm is the one package
// manager CI runs inside the author-owned app/, in the app-build job's install
// and the deps gate's audit.
const ROOT_PACKAGE_MANAGER_CONFIG_RE = /^(\.npmrc|\.yarnrc|\.yarnrc\.yml|\.pnpmfile\.cjs|pnpm-workspace\.yaml|bunfig\.toml)$/;

// Depth-first listing of everything below `root` as repo-relative POSIX paths.
// lstat semantics throughout: symlinks are reported as themselves and never
// followed, so a link to a directory outside the repo cannot make the walk
// leave it. Skips .git; reports but does not enter node_modules. A directory
// that cannot be read is NOT the same as an empty one: ENOENT (the path
// vanished between being listed and being read, a genuine race) is the only
// error swallowed — anything else (EACCES, EIO, ...) is rethrown, so the gate
// crashes red rather than silently passing a subtree it could not inspect.
//
// `isSymlink` is yielded because readdir already answered that question to
// decide whether to recurse (below), and check 1c needs the same answer: an
// lstat per entry in the caller asked the filesystem a second time for a fact
// this loop already had.
function* walkTree(root, rel = "") {
  const abs = rel ? join(root, rel) : root;
  let entries;
  try {
    entries = readdirSync(abs, { withFileTypes: true });
  } catch (err) {
    if (err.code === "ENOENT") return;
    throw err;
  }
  for (const entry of entries) {
    if (rel === "" && entry.name === ".git") continue;
    const childRel = rel ? `${rel}/${entry.name}` : entry.name;
    const isSymlink = entry.isSymbolicLink();
    yield { rel: childRel, name: entry.name, isSymlink };
    if (entry.isDirectory() && !isSymlink && entry.name !== "node_modules") yield* walkTree(root, childRel);
  }
}

/**
 * Check that `appDir` (a registered app repo) complies with the platform's
 * config-integrity requirements. Everything platform-owned (the root build
 * files, the Worker config) is SUPPLIED at build time from the platform's
 * mirror, and src/ is the platform's; this gate verifies the repo does not
 * carry shadow copies, plus the repo-local rules (CLAUDE.md headers, no
 * package-manager config, no wrangler cache dirs).
 *
 * (Check numbering has gaps: the live checks are 1, 1b, 1c, 6, 6b, 7, 7b and 8.
 * The original checks 2-6 inspected an app-owned wrangler.jsonc and were
 * retired when that file stopped being app-owned; R01 then reused 6 for the
 * root package-manager-config and .env rejection, which runs inside check
 * 1b's scan of the app root, with 6b as its nested-.npmrc companion. The
 * survivors keep their original numbers so existing references don't shift.)
 *
 * Each violation is its sentence and the repo-relative path it is about
 * (`file`, null when it names none), which the CLI's annotation carries as
 * its file= property.
 *
 * @param {string} appDir
 * @returns {{ok: boolean, violations: Array<{ message: string, file: string | null }>}}
 */
export function checkConfig(appDir) {
  /** @type {Array<{ message: string, file: string | null }>} */
  const violations = [];
  const violation = (file, message) => { violations.push({ message, file }); };

  // --- Check 1: CLAUDE.md has the shared headers + one of each variant pair ---
  const claudeMdPath = join(appDir, "CLAUDE.md");
  if (!existsSync(claudeMdPath)) {
    violation("CLAUDE.md", "CLAUDE.md is missing");
  } else {
    const claudeMd = readFileSync(claudeMdPath, "utf8");
    for (const header of REQUIRED_CLAUDE_MD_HEADERS) {
      if (!claudeMd.includes(header)) {
        violation("CLAUDE.md", `CLAUDE.md is missing required header: "${header}"`);
      }
    }
    for (const pair of CLAUDE_MD_HEADER_VARIANTS) {
      if (!pair.some((h) => claudeMd.includes(h))) {
        violation("CLAUDE.md", `CLAUDE.md is missing a required header (any variant): ${pair.map((h) => `"${h}"`).join(" or ")}`);
      }
    }
  }

  // --- Check 1b: no wrangler config file at all in the app root ---
  // NO wrangler config may exist here: the platform supplies the only
  // permitted one at build time. Anything committed could be silently
  // preferred by `wrangler deploy`'s discovery order (wrangler.json OUTRANKS
  // wrangler.jsonc), which is why this gate rejects rather than inspects: it
  // vets none of them.
  //
  // The deploy step pins --config app-worker.jsonc (hard override of
  // wrangler's discovery and redirect); this gate check is the independent
  // belt to that suspenders. Keep both. Rejecting .wrangler/ closes the redirect
  // (.wrangler/deploy/config.json) path that would reopen the bypass if
  // --config were ever dropped.
  if (existsSync(appDir)) {
    for (const entry of readdirSync(appDir, { withFileTypes: true })) {
      const name = entry.name;
      if (name === ".wrangler" && (entry.isDirectory() || entry.isSymbolicLink())) {
        violation(name,
          `.wrangler/ must not be committed: it is a wrangler-generated cache/redirect directory ` +
            `(.wrangler/deploy/config.json can redirect the deploy to an unvetted config)`,
        );
        continue;
      }
      if (name === "wrangler.jsonc") {
        violation(name,
          "delete wrangler.jsonc: the platform supplies the app's Worker config itself " +
            "(see APP-CONTRACT R7: get_app_contract, or docs/APP-CONTRACT.md)",
        );
        continue;
      }
      if (COMPETING_WRANGLER_RE.test(name)) {
        violation(name,
          `${name} is a wrangler config file: apps may not carry ANY wrangler config; the platform injects it ` +
            `(wrangler's config discovery could silently prefer it over the gate-vetted file)`,
        );
      }
      // Every package manager's project-level config is rejected here at the
      // repo root: npm, yarn classic and berry, pnpm, and bun (see
      // ROOT_PACKAGE_MANAGER_CONFIG_RE for the exact file list). An rc file
      // can redirect the registry, set install flags, or enable lifecycle
      // behavior, and npm expands ${VAR} from the environment into rc values,
      // so an rc file that reaches a step holding a credential exfiltrates it
      // on the tarball fetch (reproduced 2026-09-14). --ignore-scripts does
      // not help. A step is not the boundary: `id-token: write` has no
      // step-level scope, so every step of a job holding it sees the OIDC
      // request credential (S01, reproduced 2026-09-17), which is why the
      // app/ install runs in `app-build`, a job with no id-token grant.
      //
      // No install in CI reads a root rc file today. The build tools'
      // `npm ci` runs in $RUNNER_TEMP/build-tools, a platform-owned directory
      // outside the checkout (in app-build, and in the deploy job for a
      // container app's image push), and the app-build job's install and the
      // deps gate's audit run in app/, which its own package.json makes npm's
      // project root. The
      // one npm call at the checkout root is the app-build and deploy jobs'
      // setup-node `cache: npm` lookup (`npm config get cache`, run from the
      // workspace), and it loads a root .npmrc. Rejecting every root copy keeps a root rc
      // file out of that lookup and out of any package manager a later change
      // runs at the root. Check 6b below covers every other directory,
      // because npm reads the rc of the directory it RUNS in, not only the
      // repo root.
      //
      // wrangler loads .env/.env.* from cwd at CLI startup, and env keys the
      // step running it doesn't set are ADOPTED: a committed .env with
      // CLOUDFLARE_API_BASE_URL (or WRANGLER_DOCKER_BIN/DOCKER_HOST) redirects
      // the calls wrangler makes to an attacker host. wrangler runs at the
      // checkout root in app-build's bundle, on every push, in a job that
      // holds no credential, and in the deploy job's image push for a
      // container app, whose job env pins CLOUDFLARE_API_BASE_URL. Reject
      // like .npmrc: an unpinned build input. (2026-07-22 review find.)
      if (/^\.env(\..+)?$/.test(name)) {
        violation(name,
          `${name} must not be committed: wrangler loads .env files when it runs at the repository root (an app-set ` +
            `CLOUDFLARE_API_BASE_URL would redirect the build's own calls); remove it`,
        );
        continue;
      }
      if (ROOT_PACKAGE_MANAGER_CONFIG_RE.test(name)) {
        violation(name,
          `${name} must not be committed: package manager config is an unpinned deploy-build input; remove it`,
        );
      }
    }
  }

  // --- Checks 1c and 6b: ONE walk of the app tree ---
  // Both rules are per-entry and independent of each other, so they share the
  // single depth-first walk instead of each making a full one of its own.
  // They also shared, by copy, the same fail-closed wrapper below, whose two
  // messages differed by a single clause: one unreadable directory used to
  // produce two near-identical violations here for one cause, on top of check
  // 7's own targeted one. There is now one wrapper and one message.
  //
  // --- Check 1c: no directory symlinks anywhere in the tree ---
  // walkTree deliberately does not follow symlinks and does not descend
  // node_modules (see its own comment). Both are correct in isolation, and
  // together they left a hole: `app` as a symlink into a committed
  // node_modules subtree hid the whole app subtree from check 6b, whose
  // nested .npmrc rule is the control that keeps an author-owned .npmrc out
  // of the deploy job. Reproduced 2026-09-17 (review S01): checkConfig
  // returned ok for a fixture whose app/.npmrc was reachable by npm and
  // invisible to this gate.
  //
  // The rule is deliberately broader than "app must be a real directory". A
  // name list is a control that a future layout change can outgrow silently;
  // rejecting every directory symlink makes the walk's coverage total by
  // construction. Directory symlinks have no legitimate use in an app repo.
  //
  // A symlink to a FILE stays legal only while its target resolves INSIDE the
  // app tree (an in-tree alias.ts -> real.ts). An out-of-tree file link is
  // rejected: the build reads the target's BYTES (wrangler's default module
  // rules bundle an imported .txt/.html/.sql as content), so a link named to
  // match a bundler glob, e.g. environment.txt -> /proc/self/environ or a ../
  // escape, bakes whatever the link points at into the Worker: a file no gate
  // ever saw. (Until v0.17.0 that included the deploy job's own environment,
  // the account deploy token; the bundle is now built in a job that holds no
  // credential.)
  // The by-name checks fail closed on type, but nothing stopped an
  // arbitrary-named file link whose content the bundler then reads; this is
  // that stop. (Vuln 2026-10-18, contract 33, "not additive".) node_modules
  // is not walked here, so a link planted there at install time is caught by
  // the app-build job's own realpath guard, not this gate.
  //
  // Never followed: walkTree's readdir already reports whether an entry is a
  // symlink (that is the same answer it uses to decide not to recurse), and
  // the link is then classified by what it points AT with a stat. A DANGLING
  // link is rejected too: what it resolves to is decided by the checkout, not
  // by this gate, so it must not be given the benefit of the doubt.
  //
  // walkTree rethrows anything but ENOENT, and this walk runs before check 7,
  // so an unreadable directory anywhere below appDir (e.g. src/ with its
  // permission bits stripped) would otherwise escape as an uncaught exception
  // before check 7 gets a chance to report its own targeted message for the
  // same directory. Catch it here and fail closed with one violation covering
  // both rules.
  //
  // --- Check 6b: a nested .npmrc ANYWHERE in the tree ---
  // Check 6 inspects the root because that is where wrangler runs (no root
  // install happens: the build tools' `npm ci` runs in a platform-owned
  // directory outside the checkout). CI runs exactly one
  // package manager inside the author-owned app/ directory: npm (`npm ci` in
  // the `app-build` job, which bundles the installed tree in the same job,
  // and in the `deps` gate `npm audit`, plus, for a container app with
  // app/package.json and no lockfile, the `npm install --package-lock-only
  // --ignore-scripts` that resolves the throwaway lock it audits; a function
  // app without a lockfile is refused there, as app-build refuses it), and
  // nothing in CI runs yarn, pnpm or bun there. Do NOT read
  // this rule as guarding one step: since S01 (2026-09-17) the deploy job runs
  // no package manager in app/ at all, and this check is what keeps it that
  // way rather than a leftover from when it did. npm reads the PROJECT .npmrc
  // of the directory it is
  // invoked in and expands ${VAR} from the environment into it, so a nested
  // .npmrc is an unpinned, credential-exfiltrating deploy-build input the
  // same way the root one is. Other package managers' config at depth —
  // app/.yarnrc.yml (yarn berry's nodeLinker), app/pnpm-workspace.yaml (a
  // pnpm workspace), app/bunfig.toml — is legitimate inside a container
  // build and is left alone; only their ROOT copies are rejected, by check 6
  // above. NOT .env at depth either: wrangler reads .env from its cwd (the
  // root, which check 6 covers) and npm never reads it, so a nested
  // .env.example is harmless and common.
  //
  // The walk never follows symlinks (readdir types), fails closed on type (a
  // symlink NAMED .npmrc is rejected without resolving it), skips .git, and
  // does not descend into node_modules — nothing under a node_modules
  // directory is examined at all, because npm resolves its project rc from
  // the directory it is run in, never from inside node_modules.
  const appRoot = (() => { try { return realpathSync(appDir); } catch { return appDir; } })();
  try {
    for (const { rel, name, isSymlink } of walkTree(appDir)) {
      // check 1c: a committed directory symlink, or a file symlink whose
      // target resolves outside the app tree
      if (isSymlink) {
        const abs = join(appDir, rel);
        const target = (() => { try { return readlinkSync(abs); } catch { return "?"; } })();
        let targetIsDir = null;               // null = unresolvable (dangling)
        try {
          targetIsDir = statSync(abs).isDirectory();
        } catch {
          targetIsDir = null;
        }
        if (targetIsDir !== false) {          // a directory link, or dangling
          violation(rel,
            `${rel} is a symlink to ${targetIsDir === null ? "an unresolvable path" : "a directory"} ` +
              `(-> ${target}); directory symlinks must not be committed, because the config gate ` +
              `inspects the tree without following them and content behind one is never checked`,
          );
        } else {
          // a file link: legal only if its target resolves inside the app tree
          const real = (() => { try { return realpathSync(abs); } catch { return null; } })();
          if (real === null || !(real === appRoot || real.startsWith(appRoot + sep))) {
            violation(rel,
              `${rel} is a symlink whose target resolves outside your app (-> ${target}); ` +
                `a committed file symlink must point inside your app, because the build reads the ` +
                `target's bytes and a link out of the tree can bake files the gate never saw into your app`,
            );
          }
        }
      }
      // check 6b: a nested .npmrc (the root one is check 6's, above)
      if (name === ".npmrc" && rel.includes("/")) {
        violation(rel,
          `${rel} must not be committed: npm reads the .npmrc of whichever directory it runs in ` +
            `and expands \${VAR} from the environment into it (an unpinned deploy-build input); remove it`,
        );
      }
    }
  } catch (err) {
    violation(null,
      `config-integrity check could not fully inspect the app tree (${err.path ?? appDir}: ` +
        `${err.code ?? err}); a directory the gate cannot read fails closed`,
    );
  }

  // --- Check 7: src/ is platform-owned; nothing of the author's may exist ---
  // under it. Before v0.14.2 the platform injected its per-app gateway into a
  // directory under src/ and bundled it FROM there, inside the app checkout.
  // esbuild resolves bare imports by walking up from the importing file, so a
  // committed src/node_modules/<dep> outranked the platform's pinned copy, and
  // src/tsconfig.json (paths) or src/package.json (browser field) redirected
  // resolution the same way (2026-09-13 review F08, reproduced with wrangler
  // --dry-run 2026-09-14). No platform code is built from the checkout any
  // more, and src/ stays the platform's: the gate refuses anything under it,
  // an old gateway copy included, with the one message below.
  //
  // lstat (not existsSync): a symlink at src/ must fail closed without being
  // followed, same rule as check 8 below. An EMPTY src/ directory is
  // tolerated (nothing in it).
  let srcStat = null;
  try { srcStat = lstatSync(join(appDir, "src")); } catch (err) { if (err?.code !== "ENOENT") throw err; }
  if (srcStat) {
    let entries = [];
    let srcUnreadable = false;
    if (srcStat.isDirectory()) {
      try {
        entries = readdirSync(join(appDir, "src"));
      } catch (err) {
        // An unreadable src/ is NOT the same as an empty one: fail closed
        // rather than silently treating "we couldn't find out" as "nothing
        // there", and skip the entries-based violation below (it would
        // otherwise report an empty list for a directory we never saw into).
        srcUnreadable = true;
        violation("src",
          `delete src/: the platform owns src/ and it could not be read (${err.code ?? err}); ` +
            `a src/ the gate cannot inspect fails closed`,
        );
      }
    }
    if (!srcUnreadable && (!srcStat.isDirectory() || entries.length > 0)) {
      const what = srcStat.isDirectory() ? entries.map((n) => `src/${n}`).join(", ") : "src is not a directory";
      violation("src",
        `delete src/: the platform owns src/ (the gate refuses author files there; keep your code under app/): ${what} ` +
          `(see APP-CONTRACT R7: get_app_contract, or docs/APP-CONTRACT.md)`,
      );
    }
  }

  // --- Check 7b: scaffold/ must NOT exist. Registration prunes the ---
  // deployment-type scaffolds out of every app repo; a surviving scaffold/
  // means the prune did not happen (it failed or could not run, or the
  // template was copied by hand) and the repo is carrying BOTH variants'
  // files.
  //
  // EXCEPT while app/.needs-build exists. Registration prunes best effort, so
  // an unbuilt repo can run CI before a prune lands, or after one that could
  // not run (register_app then warns: it tells the owner of an overlay preset
  // whose repo has no scaffold/<preset>/ to delete scaffold/, and points a
  // failed prune at the contract's layout). Failing that run would redline an
  // app that has not started building. The marker is the platform's "not an
  // app yet" signal: scaffold-check skips that run's deploy anyway, and
  // deleting the marker to start building re-arms this check.
  let scaffoldPresent = false;
  try { lstatSync(join(appDir, "scaffold")); scaffoldPresent = true; } catch {}
  if (scaffoldPresent && !existsSync(join(appDir, "app", ".needs-build"))) {
    violation("scaffold",
      "delete scaffold/: the deployment-type scaffold directory is template-only; registration prunes it out of app repos",
    );
  }

  // --- Check 8: worker build inputs must NOT exist at the root. The ---
  // platform installs its build tools from the mirror into its own directory
  // outside the checkout, and puts only app-worker.jsonc and tsconfig.json at
  // the checkout root, in the app-build job, for the function shape, over any
  // author copy. An author package.json or
  // lockfile there would sit in esbuild's lookup from app/index.ts, and any of
  // the three is always stale, so the gate keeps all three out. No legacy
  // acceptance.
  //
  // Presence is an lstat, not existsSync: existsSync FOLLOWS symlinks, so a
  // dangling symlink named e.g. package.json (target absent) reports false
  // and would silently pass this check even though something occupies the
  // name. lstat never follows the link, so ANYTHING at the path (a file, a
  // directory, or a symlink of any kind, dangling included) is caught.
  for (const relPath of PINNED_BUILD_INPUT_FILES) {
    let present = false;
    try {
      lstatSync(join(appDir, relPath));
      present = true;
    } catch {
      // ENOENT: nothing at this path — compliant.
    }
    if (present) {
      violation(relPath,
        `delete ${relPath}: the platform supplies the build inputs at the repository root itself (see APP-CONTRACT R7: get_app_contract, or docs/APP-CONTRACT.md)`,
      );
    }
  }

  return { ok: violations.length === 0, violations };
}

/**
 * The CLI's lines, one per violation's message. A violation can carry a file
 * name the author wrote, so each passes through logSafe: no newline or
 * control byte reaches the runner's log, where a line that starts with a
 * workflow command is one.
 * @param {Array<{ message: string, file: string | null }>} violations
 * @returns {string[]}
 */
export function violationLines(violations) {
  return violations.map((v) => `  - ${logSafe(v.message, 1000)}`);
}

// --- CLI wrapper ---
// The plain lines list every violation in the step log; then one annotation
// each (ci/cli.mjs annotateAll, R7-5), pointing at the file it names, bounded
// to the ten a step can show, so the run page says what to fix.
if (isMainModule(import.meta.url)) {
  const [appDir] = process.argv.slice(2);
  if (!appDir) {
    console.error("Usage: node ci/check-config.mjs <app-dir>");
    process.exit(1);
  }

  const { ok, violations } = checkConfig(appDir);
  if (!ok) {
    console.error("config-integrity check FAILED:");
    for (const line of violationLines(violations)) console.error(line);
    annotateAll({
      title: "Config integrity",
      fix: "fix it as get_app_contract R7 says, then push again",
      items: violations.map((v) => ({ what: v.message, ...(v.file ? { file: v.file } : {}) })),
    });
    process.exitCode = 1;
  } else {
    console.log("config-integrity check passed.");
  }
}
