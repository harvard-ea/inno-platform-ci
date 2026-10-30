#!/usr/bin/env node
// Dependency-cooldown gate (supply-chain hygiene): flags app dependencies whose
// pinned version was published fewer than `min_release_age_days` days ago. A
// freshly-published version is the highest-risk window for a compromised
// release (typosquat, hijacked maintainer, malicious postinstall) — a short
// cooldown lets the ecosystem and scanners catch most of those before an app
// can pull them. Complements the existing deps gate (npm/pip-audit catch
// KNOWN-vulnerable versions; this catches TOO-NEW ones no one has vetted yet).
//
// Usage: node ci/check-dep-age.mjs <app-dir>
//   env MIN_RELEASE_AGE_DAYS  threshold in days (0 or unset => gate disabled)
// Exits 0 if compliant or disabled, 1 (with violations printed) otherwise.
//
//   env FUNCTION_SHAPED       "true" for a function app (the policy job's
//                             function_shaped): its devDependencies are not dated
//
// Scans exact pins only: app/requirements.txt (`name==version`) via PyPI and
// app/package-lock.json (resolved versions; a function app's devDependencies
// left out) via the npm registry. Ranges and un-pinned deps are skipped
// (nothing to date). A registry lookup that fails or returns no date is
// skipped with a warning rather than failing the deploy: a registry hiccup
// must not block a release, and the known-vulnerable gate still runs
// regardless. Zero npm dependencies: node builtins + local cli.mjs only.

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { annotate, annotateAll, isMainModule, logSafe } from "./cli.mjs";

const DAY_MS = 86_400_000;

// --- Pure parsers -----------------------------------------------------------

// Exact-pinned PyPI requirements only (`name==version`). Skips comments, blank
// lines, includes (`-r`/`-c`), options (`--…`), and any non-`==` specifier
// (ranges have no single publish date to check).
export function parseRequirements(text) {
  const out = [];
  for (const raw of String(text).split("\n")) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line || line.startsWith("-")) continue;
    const m = /^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._!+-]+)$/.exec(line);
    if (m) out.push({ ecosystem: "pypi", name: m[1].toLowerCase(), version: m[2] });
  }
  return out;
}

// Resolved versions from an npm lockfile (v2/v3 `packages` map). Three kinds
// of entry are skipped: the root package (key ""), link entries (no version),
// and workspace SOURCE entries — a path with no "node_modules/" segment, e.g.
// "packages/foo". The last one matters: it carries a real version, so a naive
// split("node_modules/").pop() yields the literal "packages/foo" and asks the
// registry to date local code that was never published (a guaranteed miss, and
// a spurious "age unknown" warning on every run). Its installed counterpart
// under node_modules/ is a link entry with no version, so nothing is lost.
// For a function app (`skipDev`), a fourth is skipped too: an entry the lock
// marks `dev`, a devDependency (or one only a devDependency pulls in). Its
// dependencies reach its Worker only through app-build's `npm ci
// --omit=dev`, so such a package never ships, and the cooldown dates only
// what ships (R7-5); `devOptional` entries stay, as --omit=dev installs them.
// A container app's devDependencies ARE dated: its Dockerfile is the
// author's, may install them to build, and so a young one can shape the
// image. The default is the container rule, so a caller that does not know
// the shape dates everything.
export function parseNpmLock(json, { skipDev = false } = {}) {
  const out = [];
  const pkgs = json && json.packages ? json.packages : {};
  for (const [path, info] of Object.entries(pkgs)) {
    if (!path || !info || typeof info.version !== "string") continue;
    if (skipDev && info.dev === true) continue;
    if (!path.includes("node_modules/")) continue;
    const name = path.split("node_modules/").pop();
    if (name) out.push({ ecosystem: "npm", name, version: info.version });
  }
  return out;
}

// Pure age decision: given entries carrying a resolved publishedAt (ms epoch),
// return the ones younger than the threshold. Entries with a null publishedAt
// were unresolved upstream and are NOT violations here (they surface as
// `skipped`). ageDays is floored for a stable, readable report.
export function evaluateAges(entries, thresholdDays, nowMs) {
  const violations = [];
  for (const e of entries) {
    if (typeof e.publishedAt !== "number") continue;
    const ageDays = Math.floor((nowMs - e.publishedAt) / DAY_MS);
    if (ageDays < thresholdDays) {
      violations.push({ name: e.name, version: e.version, ecosystem: e.ecosystem, ageDays });
    }
  }
  return violations;
}

// --- Registry lookups (I/O; injectable for tests) ---------------------------

// Per-request ceiling. Without it a hung registry stalls the gate until the
// job's own timeout kills it with no diagnosis; with it the entry simply
// resolves to null and is reported as skipped.
const REGISTRY_TIMEOUT_MS = 10_000;
const timeout = () => ({ signal: AbortSignal.timeout(REGISTRY_TIMEOUT_MS) });

async function pypiPublishedAt(fetchImpl, name, version) {
  const res = await fetchImpl(`https://pypi.org/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`, timeout());
  if (!res.ok) return null;
  const data = await res.json();
  const times = (data.urls || []).map((u) => Date.parse(u.upload_time_iso_8601)).filter((t) => !Number.isNaN(t));
  return times.length ? Math.min(...times) : null;
}

// NOTE: this must fetch the FULL packument. The abbreviated-metadata document
// (application/vnd.npm.install-v1+json) omits the `time` map entirely, so
// requesting it would make every npm lookup return null — turning the cooldown
// gate into a no-op that still prints a pass line.
async function npmPublishedAt(fetchImpl, name, version) {
  const res = await fetchImpl(`https://registry.npmjs.org/${name.replace("/", "%2F")}`, timeout());
  if (!res.ok) return null;
  const data = await res.json();
  const iso = data.time && data.time[version];
  const t = iso ? Date.parse(iso) : NaN;
  return Number.isNaN(t) ? null : t;
}

// Registry lookups run in bounded-concurrency chunks. Serial fetches added
// minutes of wall clock to every deploy of exactly the apps that opted into
// the cooldown gate (whole-repo review 2026-08-28: 800+ distinct packages at
// one full packument each), and one slow registry entry stalled the line for
// its whole 10s timeout. A failed/thrown lookup still resolves to null
// (skipped, reported), exactly as the serial loop did.
const LOOKUP_CONCURRENCY = 10;

async function resolvePublishTimes(entries, fetchImpl) {
  const resolved = [];
  const skipped = [];
  // One lookup per DISTINCT ecosystem:name@version. A lockfile lists an entry
  // per install PATH, so a dependency hoisted into several trees would
  // otherwise be fetched once per copy — same answer every time.
  const dates = new Map();
  const distinct = [];
  for (const e of entries) {
    const key = `${e.ecosystem}:${e.name}@${e.version}`;
    if (!dates.has(key)) { dates.set(key, null); distinct.push({ key, e }); }
  }
  for (let i = 0; i < distinct.length; i += LOOKUP_CONCURRENCY) {
    await Promise.all(distinct.slice(i, i + LOOKUP_CONCURRENCY).map(async ({ key, e }) => {
      try {
        dates.set(key, e.ecosystem === "pypi"
          ? await pypiPublishedAt(fetchImpl, e.name, e.version)
          : await npmPublishedAt(fetchImpl, e.name, e.version));
      } catch {
        dates.set(key, null);
      }
    }));
  }
  for (const e of entries) {
    const publishedAt = dates.get(`${e.ecosystem}:${e.name}@${e.version}`);
    if (publishedAt === null) skipped.push(e);
    resolved.push({ ...e, publishedAt });
  }
  return { resolved, skipped };
}

// --- Orchestration ----------------------------------------------------------

// `functionShaped`: the app is a function app, whose devDependencies are
// not dated (parseNpmLock's skipDev). Absent, every lock entry is dated.
export async function checkDepAge({ appDir, thresholdDays, functionShaped = false, fetchImpl = fetch, nowMs = Date.now(), readManifest }) {
  const read = readManifest ?? ((p) => (existsSync(p) ? readFileSync(p, "utf8") : null));
  const entries = [];

  const reqs = read(join(appDir, "requirements.txt"));
  if (reqs) entries.push(...parseRequirements(reqs));

  const lock = read(join(appDir, "package-lock.json"));
  let lockUsable = false;
  if (lock) {
    try { entries.push(...parseNpmLock(JSON.parse(lock), { skipDev: functionShaped })); lockUsable = true; } catch { /* malformed: handled below */ }
  }

  // package.json with NO usable lockfile, absent OR malformed, the operator's
  // own state either way: there are no exact npm versions to date, so an
  // enabled cooldown cannot be applied to npm at all. The app-build job refuses
  // a function-shaped app with no committed lockfile anyway (R11); this flag
  // exists so the CLI fails an ENABLED cooldown plainly, naming the reason,
  // instead of printing a clean-pass line over nothing. (Registry-unreachable
  // entries stay warn-only by design: a transient registry outage must not
  // block a release.)
  const unpinnedNpm = !lockUsable && !!read(join(appDir, "package.json"));

  if (entries.length === 0) return { violations: [], checked: 0, skipped: [], unpinnedNpm };

  const { resolved, skipped } = await resolvePublishTimes(entries, fetchImpl);
  const violations = evaluateAges(resolved, thresholdDays, nowMs);
  // `checked` counts entries actually DATED — an entry the registry couldn't
  // date is reported under `skipped` and must not inflate the pass message.
  return { violations, checked: resolved.length - skipped.length, skipped, unpinnedNpm };
}

// --- CLI --------------------------------------------------------------------

// The repo-relative manifest an entry of each ecosystem is pinned in, the
// file its annotation points at.
const manifestOf = (ecosystem) => (ecosystem === "pypi" ? "app/requirements.txt" : "app/package-lock.json");

// Exported so the gate's exit code is testable; the CLI block below is the
// only production caller. `appDir`/`thresholdDays`/`functionShaped` fall back
// to argv/env; only FUNCTION_SHAPED "true" reads as a function app, so a
// missing value (a policy outage) dates every entry.
export async function main({ appDir, thresholdDays, functionShaped } = {}) {
  appDir ??= process.argv[2] || "app";
  thresholdDays ??= Number(process.env.MIN_RELEASE_AGE_DAYS || 0);
  functionShaped ??= process.env.FUNCTION_SHAPED === "true";
  if (!Number.isFinite(thresholdDays) || thresholdDays <= 0) {
    console.log("dep-age: min_release_age_days is 0, so the cooldown gate is disabled; nothing to check.");
    return 0;
  }
  const { violations, checked, skipped, unpinnedNpm } = await checkDepAge({ appDir, thresholdDays, functionShaped });
  // logSafe on the name and the version, not on `ecosystem` (a literal this
  // script chose). Both come from the app's own package-lock.json or
  // requirements.txt, parsed here before npm or pip has validated anything: a
  // JSON key may contain a newline, and a newline inside a log line ends it
  // and forges a clean second command line in the run's log. Same class
  // ci/deploy-finalize.mjs documents for the declaration file. The
  // annotations (ci/cli.mjs annotate and annotateAll, R7-5) flatten their
  // values the same way, and print on stderr beside these lines.
  if (skipped.length > 0) {
    console.error(`dep-age: ${skipped.length} dependency version(s) have no publish date from the registry, so the cooldown skipped them:`);
    for (const s of skipped) console.error(`  - ${s.ecosystem}:${logSafe(s.name)}@${logSafe(s.version)}`);
    annotateAll({
      level: "warning",
      title: "Dependency age unknown",
      items: skipped.map((s) => ({
        file: manifestOf(s.ecosystem),
        what: `${s.ecosystem}:${logSafe(s.name)}@${logSafe(s.version)}: no publish date from the registry; skipped`,
      })),
    });
  }
  // Reaching here means an admin explicitly set safety.min_release_age_days:
  // they asked for a cooldown. Without a committed lockfile there are no exact
  // npm versions to date, so the cooldown cannot be applied to npm at all (the
  // app-build job refuses a function-shaped app with no committed lockfile
  // anyway, R11). Passing green would be exactly the defect this gate exists
  // to prevent: a clean report over work that was never done.
  // Note the asymmetry with the disabled case above: with the gate OFF (the
  // default) an unpinned app is fine and never reaches this branch. The gate
  // being ON is the opt-in; a committed app lockfile is not otherwise required
  // by the app contract.
  if (unpinnedNpm) {
    annotate({
      title: "Dependency cooldown",
      file: "app/package-lock.json",
      what: "app/package.json has no committed, " +
        "parseable app/package-lock.json, so there are no exact npm versions to date (and the app-build " +
        `job refuses a function-shaped app without one anyway, R11). This app cannot satisfy the ${thresholdDays}-day cooldown its ` +
        "safety.min_release_age_days setting requires",
      fix: "commit app/package-lock.json, or ask a platform admin to set safety.min_release_age_days to 0 for this app",
    });
  }
  // Violations print even when unpinnedNpm already failed the run: a Python
  // app with cooldown violations AND an unpinned package.json should learn
  // about both now, not discover the second failure after fixing the first.
  if (violations.length > 0) {
    console.error(`dep-age: ${violations.length} dependency version(s) younger than the ${thresholdDays}-day cooldown:`);
    for (const v of violations) {
      // logSafe for the same reason as the skipped lines above: Actions
      // reads workflow commands off stderr too, so an author-chosen newline
      // in a package name forges one from this line just as well.
      console.error(`  - ${v.ecosystem}:${logSafe(v.name)}@${logSafe(v.version)} published ${v.ageDays} day(s) ago`);
    }
    // The file the young versions are pinned in, when they share one.
    const files = new Set(violations.map((v) => manifestOf(v.ecosystem)));
    annotate({
      title: "Dependency cooldown",
      file: files.size === 1 ? [...files][0] : undefined,
      what: `${violations.length} dependency version(s) younger than the ${thresholdDays}-day cooldown`,
      fix: "pin an older, vetted version, or ask a platform admin to lower safety.min_release_age_days for this app",
    });
  }
  if (unpinnedNpm || violations.length > 0) return 1;
  console.log(`dep-age: ${checked} pinned dependency version(s) checked; all at least ${thresholdDays} day(s) old.`);
  return 0;
}

if (isMainModule(import.meta.url)) {
  // A crash is the gate's failure too, said the way its verdicts are (an
  // unreadable manifest's error can quote what it read, so it is flattened).
  main().then((code) => process.exit(code)).catch((e) => {
    annotate({
      title: "Dependency cooldown",
      what: logSafe(String(e?.message ?? e)),
      fix: "re-run the workflow; if it repeats, ask a platform admin",
    });
    process.exit(1);
  });
}
