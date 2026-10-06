#!/usr/bin/env node
// Config-integrity gate: verifies an app repo has not weakened the security
// posture the platform requires — required CLAUDE.md guidance present, and no
// platform-owned build input vendored into the app repo (gateway source,
// worker build inputs, and ANY wrangler config; the platform injects all of
// them at build time from the promoted gateway.ref), nothing of the author's
// under src/ (reserved for the gateway, which the deploy builds outside the
// checkout), and no package-manager configuration at any depth (npm expands
// ${VAR} from the environment into it). The live checks are 1, 1b, 1c, 6, 6b,
// 7, 7b and 8; see checkConfig's own note on the numbering.
//
// Usage: node ci/check-config.mjs <app-dir>
// Exits 0 if compliant, 1 (with violations printed) otherwise.
//
// Zero npm dependencies: node:fs, node:path builtins plus the local (also
// zero-dependency) ci/cli.mjs helper only.

import { existsSync, lstatSync, readFileSync, readdirSync, readlinkSync, statSync } from "node:fs";
import { join } from "node:path";
import { isMainModule } from "./cli.mjs";

// Headers every app's CLAUDE.md must carry, regardless of deployment type.
const REQUIRED_CLAUDE_MD_HEADERS = [
  "## Innovation Platform App",
  "## Identity (do not build auth)",
  "## What CI enforces",
];

// Type-variant header groups: each group carries the same safety guidance for
// its runtime, and ANY member satisfies the gate. The gate stays
// deliberately type-blind — it must not depend on the broker's policy fetch
// (which can fall back to 'container' on an outage) to know which variant to
// demand, and pre-scaffold apps all carry the container member. "## Worker
// contract" is the legacy heading of "## Function contract" (the 'worker'
// preset was renamed 'function' 2026-07-30): scaffolds emit the new heading,
// but existing app repos keep their CLAUDE.md forever, so both satisfy.
const CLAUDE_MD_HEADER_VARIANTS = [
  ["## Persistence (use the storage client)", "## Persistence (use your bindings)"],
  ["## Container contract", "## Function contract", "## Worker contract"],
];

/**
 * Strip `//` and `/* *\/` comments from a JSONC string, without touching
 * `//` or `/*` sequences that appear inside string literals.
 */
export function stripJsonComments(text) {
  let out = "";
  let inString = false;
  let inLineComment = false;
  let inBlockComment = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];

    if (inLineComment) {
      if (ch === "\n") {
        inLineComment = false;
        out += ch;
      }
      continue;
    }

    if (inBlockComment) {
      if (ch === "*" && next === "/") {
        inBlockComment = false;
        i++;
      }
      continue;
    }

    if (inString) {
      out += ch;
      if (ch === "\\") {
        // preserve the escaped character verbatim (e.g. \" or \\)
        out += next;
        i++;
        continue;
      }
      if (ch === '"') inString = false;
      continue;
    }

    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }
    if (ch === "/" && next === "/") {
      inLineComment = true;
      i++;
      continue;
    }
    if (ch === "/" && next === "*") {
      inBlockComment = true;
      i++;
      continue;
    }
    out += ch;
  }

  return out;
}


// Worker build-input files that are platform-owned: the deploy job copies the
// promoted gateway's package.json, package-lock.json and tsconfig.json into
// the checkout root at build time (they feed setup-node's cache key and the
// function-shaped app Worker's tsconfig lookup), and wrangler runs with that
// root as its cwd. A vendored copy would shadow them and is always stale, so
// check 8 rejects any of them outright. They are not template files any more;
// .github/workflows/ci.yml's template-drift reverse walk says so too.
const PINNED_BUILD_INPUT_FILES = ["package.json", "package-lock.json", "tsconfig.json"];

// wrangler discovers its config in the app root as `wrangler.json ??
// wrangler.jsonc ?? wrangler.toml`, honoring env-variants too. The platform
// injects the ONLY permitted config (wrangler.jsonc, from the promoted
// gateway.ref) at deploy time — so ANY wrangler config committed to an app
// repo is a shadow/bypass and is rejected. `--config wrangler.jsonc` at
// deploy pins the file as the belt to this suspenders.
// Matches a wrangler config file we must reject: the bare `wrangler.json` /
// `wrangler.toml`, or any env-variant `wrangler.<something>.(json|jsonc|toml)`.
// wrangler.jsonc itself never matches (no middle segment, and .jsonc is only
// reached via the env-variant arm which requires a `.<env>.` in between).
const COMPETING_WRANGLER_RE = /^wrangler\.(json|toml|.+\.(json|jsonc|toml))$/;

// Every package manager's project-level configuration, rejected at the repo
// ROOT: wrangler runs with the checkout root as its cwd, the deploy job copies
// the gateway's build inputs there at build time (no root install happens any
// more, R02), and a .pnpmfile.cjs is arbitrary JavaScript an install would
// execute. At depth only .npmrc matters (check 6b): npm is the one package
// manager the deploy job runs inside the author-owned app/.
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
 * config-integrity requirements. Everything platform-owned (gateway source,
 * worker build inputs, wrangler.jsonc) is INJECTED at build time from the
 * promoted gateway.ref — this gate verifies the repo does not carry shadow
 * copies, plus the repo-local rules (CLAUDE.md headers, no package-manager
 * config, no wrangler cache dirs).
 *
 * (Check numbering has gaps: the live checks are 1, 1b, 1c, 6, 6b, 7, 7b and 8.
 * The original checks 2-6 inspected an app-owned wrangler.jsonc and were
 * retired when that file stopped being app-owned; R01 then reused 6 for the
 * root package-manager-config and .env rejection, which runs inside check
 * 1b's scan of the app root, with 6b as its nested-.npmrc companion. The
 * survivors keep their original numbers so existing references don't shift.)
 *
 * @param {string} appDir
 * @returns {{ok: boolean, violations: string[]}}
 */
export function checkConfig(appDir) {
  const violations = [];

  // --- Check 1: CLAUDE.md has the shared headers + one of each variant pair ---
  const claudeMdPath = join(appDir, "CLAUDE.md");
  if (!existsSync(claudeMdPath)) {
    violations.push("CLAUDE.md is missing");
  } else {
    const claudeMd = readFileSync(claudeMdPath, "utf8");
    for (const header of REQUIRED_CLAUDE_MD_HEADERS) {
      if (!claudeMd.includes(header)) {
        violations.push(`CLAUDE.md is missing required header: "${header}"`);
      }
    }
    for (const pair of CLAUDE_MD_HEADER_VARIANTS) {
      if (!pair.some((h) => claudeMd.includes(h))) {
        violations.push(`CLAUDE.md is missing a required header (any variant): ${pair.map((h) => `"${h}"`).join(" or ")}`);
      }
    }
  }

  // --- Check 1b: no wrangler config file at all in the app root ---
  // NO wrangler config may exist here — the platform injects the only
  // permitted one at deploy time from the promoted gateway.ref. Anything
  // committed could be silently preferred by `wrangler deploy`'s discovery
  // order (wrangler.json OUTRANKS wrangler.jsonc), which is why this gate
  // rejects rather than inspects: it vets none of them.
  //
  // The deploy step pins --config wrangler.jsonc (hard override of wrangler's
  // discovery + redirect); this gate check is the independent belt to that
  // suspenders — keep both. Rejecting .wrangler/ closes the redirect
  // (.wrangler/deploy/config.json) path that would reopen the bypass if
  // --config were ever dropped.
  if (existsSync(appDir)) {
    for (const entry of readdirSync(appDir, { withFileTypes: true })) {
      const name = entry.name;
      if (name === ".wrangler" && (entry.isDirectory() || entry.isSymbolicLink())) {
        violations.push(
          `.wrangler/ must not be committed — it is a wrangler-generated cache/redirect directory ` +
            `(.wrangler/deploy/config.json can redirect the deploy to an unvetted config)`,
        );
        continue;
      }
      if (name === "wrangler.jsonc") {
        violations.push(
          "delete wrangler.jsonc — the platform injects wrangler.jsonc at build time from the promoted gateway.ref " +
            "(see APP-CONTRACT R7 — get_app_contract, or docs/APP-CONTRACT.md)",
        );
        continue;
      }
      if (COMPETING_WRANGLER_RE.test(name)) {
        violations.push(
          `${name} is a wrangler config file — apps may not carry ANY wrangler config; the platform injects it ` +
            `(wrangler's config discovery could silently prefer it over the gate-vetted file)`,
        );
      }
      // Every package manager's project-level config is rejected here at the
      // repo root — npm, yarn classic and berry, pnpm, and bun (see
      // ROOT_PACKAGE_MANAGER_CONFIG_RE for the exact file list). npm and
      // yarn classic's rc files are an unpinned input to `npm ci` in the
      // deploy job — they can redirect the registry, set install flags, or
      // enable lifecycle behavior. npm also expands ${VAR} from the environment
      // into rc values, so an rc file that reaches a step holding a credential
      // exfiltrates it on the tarball fetch (reproduced 2026-09-14; the
      // function-shaped app/ install has since moved out of the deploy job
      // entirely, into `app-deps`, which holds no id-token grant. A step was
      // never enough: `id-token: write` has no step-level scope, so every step
      // of a job holding it sees the OIDC request credential, which is S01,
      // reproduced 2026-09-17). --ignore-scripts does not help. Root-level
      // here; check 6b below
      // covers every other directory, because npm reads the rc of the directory
      // it RUNS in, not only the repo root.
      // wrangler loads .env/.env.* from cwd at CLI startup, and env keys the
      // deploy step doesn't set are ADOPTED — a committed .env with
      // CLOUDFLARE_API_BASE_URL (or WRANGLER_DOCKER_BIN/DOCKER_HOST) redirects
      // API calls, bearer token included, to an attacker host. Reject like
      // .npmrc: an unpinned deploy-build input. (2026-07-22 review find.)
      if (/^\.env(\..+)?$/.test(name)) {
        violations.push(
          `${name} must not be committed — wrangler loads .env files at deploy time (an app-set ` +
            `CLOUDFLARE_API_BASE_URL would redirect API calls, account token included); remove it`,
        );
        continue;
      }
      if (ROOT_PACKAGE_MANAGER_CONFIG_RE.test(name)) {
        violations.push(
          `${name} must not be committed — package manager config is an unpinned deploy-build input; remove it`,
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
  // A symlink to a FILE stays legal: every by-name check already lstats and
  // fails closed on type, so a file link cannot hide content from anything.
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
  // install happens any more: the gateway's own `npm ci` runs in a
  // platform-owned directory outside the checkout, R02). CI runs exactly one
  // package manager inside the author-owned app/ directory: npm (`npm ci` in
  // the `app-deps` job, whose installed tree the deploy job then restores;
  // plus `npm audit` in the `deps` gate. The `npm install` fallback is gone
  // since R11), and nothing in CI runs yarn, pnpm or bun there. Do NOT read
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
  try {
    for (const { rel, name, isSymlink } of walkTree(appDir)) {
      // check 1c: a committed directory symlink
      if (isSymlink) {
        const abs = join(appDir, rel);
        let targetIsDir = null;               // null = unresolvable (dangling)
        try {
          targetIsDir = statSync(abs).isDirectory();
        } catch {
          targetIsDir = null;
        }
        if (targetIsDir !== false) {          // a link to a file is allowed
          const target = (() => { try { return readlinkSync(abs); } catch { return "?"; } })();
          violations.push(
            `${rel} is a symlink to ${targetIsDir === null ? "an unresolvable path" : "a directory"} ` +
              `(-> ${target}); directory symlinks must not be committed, because the config gate ` +
              `inspects the tree without following them and content behind one is never checked`,
          );
        }
      }
      // check 6b: a nested .npmrc (the root one is check 6's, above)
      if (name === ".npmrc" && rel.includes("/")) {
        violations.push(
          `${rel} must not be committed — npm reads the .npmrc of whichever directory it runs in ` +
            `and expands \${VAR} from the environment into it (an unpinned deploy-build input); remove it`,
        );
      }
    }
  } catch (err) {
    violations.push(
      `config-integrity check could not fully inspect the app tree (${err.path ?? appDir}: ` +
        `${err.code ?? err}); a directory the gate cannot read fails closed`,
    );
  }

  // --- Check 7: src/ is platform-owned; nothing of the author's may exist ---
  // under it. Before v0.14.2 the platform injected the promoted gateway (config
  // gateway.ref) into src/gateway/ and bundled it FROM there, inside the app
  // checkout. esbuild resolves bare imports by walking up from the importing
  // file, so a committed src/node_modules/<dep> outranked the platform's
  // pinned copy, and src/tsconfig.json (paths) or src/package.json (browser
  // field) redirected resolution the same way: an author could replace hono or
  // jose inside their own app's authentication perimeter while the deployment
  // recorded a legitimate gateway ref (2026-09-13 review F08, reproduced with
  // wrangler --dry-run 2026-09-14). The deploy job now builds the gateway in a
  // platform-owned directory outside the checkout (R02), which takes the
  // author's tree off the resolution path; this check and the deploy job's
  // wipe of src/ stay as the belt. A vendored src/gateway/ keeps its original
  // message.
  //
  // lstat (not existsSync): a symlink at src/ or src/gateway must fail closed
  // without being followed — same rule as check 8 below. An EMPTY src/
  // directory is tolerated (nothing to shadow with).
  let srcStat = null;
  try { srcStat = lstatSync(join(appDir, "src")); } catch (err) { if (err?.code !== "ENOENT") throw err; }
  if (srcStat) {
    let entries = [];
    let srcUnreadable = false;
    if (srcStat.isDirectory()) {
      try {
        entries = readdirSync(join(appDir, "src")).filter((n) => n !== "gateway");
      } catch (err) {
        // An unreadable src/ is NOT the same as an empty one: fail closed
        // rather than silently treating "we couldn't find out" as "nothing to
        // shadow with", and skip the entries-based violation below (it would
        // otherwise report an empty list for a directory we never saw into).
        srcUnreadable = true;
        violations.push(
          `delete src/ — the platform owns src/ and it could not be read (${err.code ?? err}); ` +
            `a src/ the gate cannot inspect fails closed`,
        );
      }
    }
    // Only probe src/gateway once src/ is known to be a readable directory —
    // otherwise (src is a file, or unreadable) the readdirSync above has
    // already produced the right violation, and lstat-ing a "gateway" child
    // of something that isn't a normal directory would throw ENOTDIR/EACCES
    // for a fact we already have, not a new one.
    let gatewayPresent = false;
    if (srcStat.isDirectory() && !srcUnreadable) {
      try {
        lstatSync(join(appDir, "src", "gateway"));
        gatewayPresent = true;
      } catch (err) {
        if (err?.code !== "ENOENT") throw err;
      }
    }
    if (gatewayPresent) {
      violations.push(
        "delete src/gateway/ — the platform injects the gateway at build time (see APP-CONTRACT R7 — get_app_contract, or docs/APP-CONTRACT.md)",
      );
    }
    if (!srcUnreadable && (!srcStat.isDirectory() || entries.length > 0)) {
      const what = srcStat.isDirectory() ? entries.map((n) => `src/${n}`).join(", ") : "src is not a directory";
      violations.push(
        `delete src/ — the platform owns src/ (reserved for the gateway: the deploy builds it outside your checkout ` +
          `and wipes src/, and the gate refuses author files there so none can shadow the gateway's dependencies ` +
          `or compiler configuration): ${what} ` +
          `(see APP-CONTRACT R7 — get_app_contract, or docs/APP-CONTRACT.md)`,
      );
    }
  }

  // --- Check 7b: scaffold/ must NOT exist — registration prunes the ---
  // deployment-type scaffolds out of every app repo; a surviving
  // scaffold/ means the prune failed (or the template was copied by hand)
  // and the repo is carrying BOTH variants' files.
  //
  // EXCEPT while app/.needs-build exists: the template-generation commit (the
  // user's "Use this template") fires its own
  // CI run before registration's prune commit lands, and that run checks out
  // the pristine, unpruned template — failing it would redline every new
  // app's very first run for a transient state that only exists until
  // registration's prune commit lands. The marker is the platform's existing
  // "not an app yet" signal (scaffold-check skips deploys on it), and deleting
  // it to start building re-arms this check; a genuinely failed prune can't
  // deploy anyway (registration halts before the deploy prerequisites exist).
  let scaffoldPresent = false;
  try { lstatSync(join(appDir, "scaffold")); scaffoldPresent = true; } catch {}
  if (scaffoldPresent && !existsSync(join(appDir, "app", ".needs-build"))) {
    violations.push(
      "delete scaffold/ — the deployment-type scaffold directory is template-only; registration prunes it out of app repos",
    );
  }

  // --- Check 8: worker build inputs must NOT exist — the platform injects ---
  // package.json / package-lock.json / tsconfig.json at build time from the
  // promoted gateway ref; a vendored copy would shadow them and is always
  // stale. No legacy acceptance.
  //
  // Presence is an lstat, not existsSync: existsSync FOLLOWS symlinks, so a
  // dangling symlink named e.g. package.json (target absent) reports false
  // and would silently pass this check even though something occupies the
  // name. lstat never follows the link, so ANYTHING at the path — a file, a
  // directory, or a symlink of any kind (dangling included) — is caught.
  for (const relPath of PINNED_BUILD_INPUT_FILES) {
    let present = false;
    try {
      lstatSync(join(appDir, relPath));
      present = true;
    } catch {
      // ENOENT: nothing at this path — compliant.
    }
    if (present) {
      violations.push(
        `delete ${relPath} — the platform injects worker build inputs at build time (see APP-CONTRACT R7 — get_app_contract, or docs/APP-CONTRACT.md)`,
      );
    }
  }

  return { ok: violations.length === 0, violations };
}

// --- CLI wrapper ---
if (isMainModule(import.meta.url)) {
  const [appDir] = process.argv.slice(2);
  if (!appDir) {
    console.error("Usage: node ci/check-config.mjs <app-dir>");
    process.exit(1);
  }

  const { ok, violations } = checkConfig(appDir);
  if (!ok) {
    console.error("config-integrity check FAILED:");
    for (const violation of violations) console.error(`  - ${violation}`);
    process.exit(1);
  }
  console.log("config-integrity check passed.");
}
