#!/usr/bin/env node
// The safety sweep's findings in the platform's SweepFinding shape
// (src/advisory.ts), for both of its lanes, and their one poster:
//   - the image lane: trivy's JSON report over an app's stored SBOM
//     (normalizeTrivy), posted to /sweep/results;
//   - the deps lane: `npm audit --json` over a function app's lockfile at its
//     live release tag (normalizeNpm), posted to /sweep/deps-results.
// The Worker applies policy centrally (the severity floor and the admin
// ignores) and drives the vulnerable episode; this script only delivers data.
// A {stale:true} answer is SUCCESS: the app was redeployed, stopped or
// reconfigured after the manifest, and the scan is deliberately discarded.
// A scan the job could not finish is posted as a failure (postFailure), which
// the platform stamps the app for and records nothing else for, so a failing
// scan waits out its interval rather than keeping the sweep due every hour
// (R13-14, v0.17.7).
// Each lane keeps the first MAX_FINDINGS findings by severity rank (not by
// name: the jq block this replaces sorted alphabetically, which put LOW
// before MEDIUM and was right only because trivy ran with HIGH,CRITICAL),
// titles cut at MAX_TITLE_CHARS, to bound the POST; the Worker re-filters
// either way.
//
// Tenant CI's deps gate reads the same npm normalizer (`gate`), so
// safety.ignore.deps.* applies to npm exactly as `pip-audit --ignore-vuln`
// applies it, and the gate and the sweep judge one shape. The gate's verdict
// follows the one annotation rule (ci/cli.mjs annotate, R7-5): a plain line
// per surviving advisory, naming the version that fixes it, then one
// annotation naming the lockfile, the first ten advisories and the remedy; a
// report it cannot read is annotated with the re-run remedy. The sweep's
// modes (post, no-deps, post-failed) run in the platform's own workflow and
// print their failures plainly.
//
// Usage:
//   node ci/sweep-results.mjs gate <auditJson>     env IGNORES: space-separated advisory ids
//     exit 1 if any HIGH/CRITICAL advisory survives the ignores, with the
//     annotation the header names
//   node ci/sweep-results.mjs post <trivy|npm> <brokerUrl> <app> <deploymentId> <reportPath> <token>
//     normalize the lane's report and POST it
//   node ci/sweep-results.mjs no-deps <brokerUrl> <app> <deploymentId> <token>
//     record a function app with no app/package.json at its release tag as
//     swept clean, with no audit (OPEN 87): the deps lane's POST with no findings
//   node ci/sweep-results.mjs post-failed <trivy|npm> <brokerUrl> <app> <reason> <token>
//     post that the lane's scan of the app could not finish, and why (at most
//     200 characters): the platform stamps the app and records no finding
// `token` is the GitHub Actions OIDC token (audience inno-platform-sweep). A
// report the scanner did not finish (npm audit's top-level `error`, or a file
// that is not a trivy report), and one that parses but whose nested structure
// is not the scanner's (Codex Part A on v0.17.3, finding 2), is a hard
// failure in every mode, never "clean": the gate does not pass it and the
// sweep does not post it, so it cannot clear a vulnerability episode.
//
// Until v0.17.3 the image lane built its findings in jq inside
// safety-sweep.yml and posted through ci/sweep-post.mjs, and the deps lane had
// ci/deps-normalize.mjs (R7-12).

import { readFile } from "node:fs/promises";
import { brokerPost } from "./broker-post.mjs";
import { ANNOTATION_WHAT_MAX, annotate, isMainModule, logSafe, parseIntegerArg } from "./cli.mjs";

/** The most findings one POST carries. */
export const MAX_FINDINGS = 200;
/** The most of an advisory's title a finding carries. */
export const MAX_TITLE_CHARS = 120;
/**
 * The most of a failure's reason a post carries: the most the results routes
 * take (src/routes/sweep.ts MAX_FAILURE_REASON_CHARS, held equal by
 * test/constant-parity.node.test.ts), so a failure post is never refused for
 * its length.
 */
export const MAX_FAILURE_REASON_CHARS = 200;

// Severity rank, most severe first. trivy says MEDIUM where npm says
// MODERATE; anything else (trivy's UNKNOWN) sorts last.
const RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, MODERATE: 2, LOW: 3, INFO: 4 };
const rank = (f) => RANK[f.severity] ?? 9;

/** Where each lane's results go, and the label its errors carry. */
export const LANES = {
  trivy: { path: "/sweep/results", label: "sweep-results" },
  npm: { path: "/sweep/deps-results", label: "deps-results" },
};

// A finding with only the fields that hold a value: the platform reads an
// absent field and a null one alike, and an object of set fields is the
// SweepFinding shape exactly.
const finding = (fields) => Object.fromEntries(Object.entries(fields).filter(([, v]) => v !== undefined && v !== null));
const str = (v) => (typeof v === "string" ? v : undefined);
// A JSON object: not null, not an array.
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const filled = (v) => typeof v === "string" && v !== "";
const title = (v) => (typeof v === "string" ? v.slice(0, MAX_TITLE_CHARS) : undefined);
// Stable, so two findings of one severity keep the report's order.
const bySeverity = (findings) => [...findings].sort((a, b) => rank(a) - rank(b)).slice(0, MAX_FINDINGS);

/**
 * Flatten trivy's JSON report (`trivy sbom --format json`) into SweepFinding
 * rows: one per vulnerability of every Results entry, carrying that entry's
 * Class and Type (the remediation advice's lane marker, src/advisory.ts).
 * Throws on anything but a JSON object carrying trivy's numeric
 * SchemaVersion, so a truncated, empty or wrong file never reads as a clean
 * scan, and on a report whose nested structure is not trivy's: a Results
 * that is not an array (null included), a Results entry that is not an
 * object or whose Vulnerabilities is not an array, and a vulnerability that
 * is not an object or lacks its VulnerabilityID or its Severity, which trivy
 * writes on every one. A Results or a Vulnerabilities that is absent reads
 * as none: trivy's Go structs mark both omitempty, so a scan that found no
 * target to report has no Results and a target with no findings has no
 * Vulnerabilities. trivy never writes a null; a null Vulnerabilities still
 * reads as none, as it always has. The other fields are optional: one that
 * is not a string is left out of the finding.
 *
 * @param {any} report - parsed trivy JSON
 * @returns {Array<{id: string, pkg?: string, installed?: string, fixed?: string, severity: string, title?: string, class?: string, type?: string}>}
 */
export function normalizeTrivy(report) {
  if (!isObject(report) || typeof report.SchemaVersion !== "number") {
    throw new Error("the scan is not a trivy JSON report (expected an object with a numeric SchemaVersion)");
  }
  const malformed = (what) => new Error(`the trivy report is malformed (${what}), so it is not read as a scan`);
  // A list trivy leaves out when it is empty: absent reads as none, and
  // anything else must be an array, except a null Vulnerabilities (above).
  const listOrNone = (value, at, nullIsNone) => {
    if (value === undefined || (nullIsNone && value === null)) return [];
    if (!Array.isArray(value)) throw malformed(`${at} is not an array`);
    return value;
  };
  const out = [];
  for (const [i, r] of listOrNone(report.Results, "Results", false).entries()) {
    if (!isObject(r)) throw malformed(`Results[${i}] is not an object`);
    for (const [j, v] of listOrNone(r.Vulnerabilities, `Results[${i}].Vulnerabilities`, true).entries()) {
      const at = `Results[${i}].Vulnerabilities[${j}]`;
      if (!isObject(v)) throw malformed(`${at} is not an object`);
      if (!filled(v.VulnerabilityID)) throw malformed(`${at} has no VulnerabilityID`);
      if (!filled(v.Severity)) throw malformed(`${at} has no Severity`);
      out.push(finding({
        id: v.VulnerabilityID,
        pkg: str(v.PkgName),
        installed: str(v.InstalledVersion),
        fixed: str(v.FixedVersion),
        severity: v.Severity.toUpperCase(),
        title: title(v.Title),
        class: str(r.Class),
        type: str(r.Type),
      }));
    }
  }
  return bySeverity(out);
}

/**
 * Flatten `npm audit --json` (auditReportVersion 2) into SweepFinding rows:
 * one per advisory id (string vias are transitive references, skipped),
 * severity uppercased. Throws when the report carries a top-level `error`
 * (npm audit did not run: never "clean"), and on anything but a JSON object
 * carrying auditReportVersion 2 and a `vulnerabilities` object (empty when
 * nothing is found), so a truncated, empty or wrong file never reads as a
 * clean audit, as normalizeTrivy refuses one. Throws too on a report whose
 * nested structure is not npm's: a vulnerability entry that is not an
 * object, whose `via` is not an array, or that carries a severity and no
 * via; a via that is neither a dependency's name nor an advisory object;
 * and an advisory with no id (neither a GHSA url nor a source) or no
 * severity (its own, else its entry's). npm writes every entry with a `via`
 * array, and one with no via only once it has dropped every advisory, when
 * its severity is null; such an entry reads as no findings, as before.
 *
 * @param {any} audit - parsed `npm audit --json` output
 * @returns {Array<{id: string, pkg?: string, fixed?: string, fix_available: boolean, severity: string, title?: string, class: string, type: string}>}
 */
export function normalizeNpm(audit) {
  if (audit && typeof audit === "object" && audit.error) {
    const e = audit.error;
    throw new Error(`npm audit did not run: ${e.code ?? ""} ${e.summary ?? ""}`.trim());
  }
  if (!isObject(audit) || audit.auditReportVersion !== 2 || !isObject(audit.vulnerabilities)) {
    throw new Error("the report is not an npm audit report (expected an object with auditReportVersion 2 and a " +
      "vulnerabilities object)");
  }
  // The entry's name is the report's, so logSafe and JSON quoting keep a
  // newline in it from ending the error line and forging a workflow command.
  const malformed = (what) => new Error(`the npm audit report is malformed (${what}), so it is not read as an audit`);
  const byId = new Map();
  for (const [name, v] of Object.entries(audit.vulnerabilities)) {
    const at = `vulnerabilities[${JSON.stringify(logSafe(name, 60))}]`;
    if (!isObject(v)) throw malformed(`${at} is not an object`);
    if (!Array.isArray(v.via)) throw malformed(`${at}.via is not an array`);
    if (v.via.length === 0 && v.severity !== null) throw malformed(`${at} has a severity and no via`);
    for (const [j, via] of v.via.entries()) {
      if (typeof via === "string") continue; // a dependency's name: its advisory is that dependency's own entry
      if (!isObject(via)) throw malformed(`${at}.via[${j}] is neither a dependency's name nor an advisory`);
      const tail = typeof via.url === "string" ? via.url.split("/").pop() : "";
      const id = tail && tail.startsWith("GHSA-") ? tail : String(via.source ?? "");
      if (!id) throw malformed(`${at}.via[${j}] has neither a GHSA url nor a source`);
      const severity = [via.severity, v.severity].find(filled);
      if (!severity) throw malformed(`${at}.via[${j}] has no severity`);
      if (byId.has(id)) continue;
      const fix = v.fixAvailable;
      byId.set(id, finding({
        id,
        pkg: str(via.name),
        fixed: fix && typeof fix === "object" ? `${fix.name}@${fix.version}` : undefined,
        // npm's fixAvailable is `true`, `false`, or an object (fix pinned to
        // a specific top-level version), collapsed to a plain boolean. A
        // MISSING key (fix === undefined) reads as fixable too, matching
        // remediationClass's absent-means-fixable policy (src/advisory.ts).
        fix_available: fix !== false,
        severity: severity.toUpperCase(),
        title: title(via.title),
        // Lane marker for remediation advice (src/advisory.ts): everything
        // npm audit reports is an app dependency.
        class: "lang-pkgs",
        type: "npm",
      }));
    }
  }
  return bySeverity([...byId.values()]);
}

/**
 * The deploy gate's verdict filter: HIGH/CRITICAL advisories not ignored.
 *
 * @param {ReturnType<typeof normalizeNpm>} findings
 * @param {string[]} ignores - advisory ids from safety.ignore.deps.*
 * @returns {ReturnType<typeof normalizeNpm>}
 */
export function gateSurvivors(findings, ignores) {
  return findings.filter((f) =>
    (f.severity === "HIGH" || f.severity === "CRITICAL") && !ignores.includes(f.id));
}

/**
 * POST {app, deployment_id, findings} to the lane's results endpoint, with
 * the OIDC bearer. The one poster for both lanes.
 *
 * @param {object} req
 * @param {string} req.base - broker base URL
 * @param {string} req.token - GitHub Actions OIDC token (sweep audience)
 * @param {"trivy"|"npm"} req.lane
 * @param {string} req.app
 * @param {number} req.deploymentId
 * @param {Array<object>} req.findings
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} [fetcher]
 *   - injectable for testing; defaults to global fetch
 * @returns {Promise<any>} the parsed JSON response body (e.g. { recorded } or { stale })
 */
export async function postFindings({ base, token, lane, app, deploymentId, findings }, fetcher = fetch) {
  return brokerPost({ ...laneOf(lane), base, token, body: { app, deployment_id: deploymentId, findings } }, fetcher);
}

/**
 * POST {app, failed: true, reason} to the lane's results endpoint, with the
 * OIDC bearer: the lane's scan of the app could not finish. The platform
 * stamps the app and records nothing else. The reason is flattened and cut
 * to MAX_FAILURE_REASON_CHARS (logSafe), the most the routes take.
 *
 * @param {object} req
 * @param {string} req.base - broker base URL
 * @param {string} req.token - GitHub Actions OIDC token (sweep audience)
 * @param {"trivy"|"npm"} req.lane
 * @param {string} req.app
 * @param {string} req.reason - what could not finish, in the workflow's words
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} [fetcher]
 * @returns {Promise<any>} the parsed JSON response body ({ stamped: true })
 */
export async function postFailure({ base, token, lane, app, reason }, fetcher = fetch) {
  return brokerPost({ ...laneOf(lane), base, token, body: { app, failed: true, reason: logSafe(reason, MAX_FAILURE_REASON_CHARS) } }, fetcher);
}

// The lane's endpoint and label, or a refusal naming the two there are.
function laneOf(lane) {
  const to = Object.hasOwn(LANES, lane) ? LANES[lane] : undefined;
  if (!to) throw new Error(`unknown lane ${JSON.stringify(logSafe(lane, 40))}: use "trivy" or "npm"`);
  return to;
}

const NORMALIZERS = { trivy: normalizeTrivy, npm: normalizeNpm };
const USAGE = {
  gate: "Usage: node ci/sweep-results.mjs gate <auditJson>  (env IGNORES = space-separated ids)",
  post: "Usage: node ci/sweep-results.mjs post <trivy|npm> <brokerUrl> <app> <deploymentId> <reportPath> <token>",
  "no-deps": "Usage: node ci/sweep-results.mjs no-deps <brokerUrl> <app> <deploymentId> <token>",
  "post-failed": "Usage: node ci/sweep-results.mjs post-failed <trivy|npm> <brokerUrl> <app> <reason> <token>",
};

async function readReport(path) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch (err) {
    throw new Error(`could not read/parse the report at ${path}: ${String(err?.message ?? err)}`);
  }
}

// The most advisories the gate's annotation names; the step log lists them all.
const GATE_NAMED = 10;

// The gate's words for an advisory, `<id> (<package>)`. logSafe on every
// field, here and in survivorLine: each is `npm audit` output, which reports
// whatever the app's own dependency tree named, and a newline inside a log
// line ends it and forges a clean second command line in the run's log. Same
// class ci/deploy-finalize.mjs documents for the declaration file.
const named = (f) => `${logSafe(f.id)}${f.pkg ? ` (${logSafe(f.pkg)})` : ""}`;

/**
 * The gate annotation's what: the count, then the advisories by name, at
 * most GATE_NAMED of them and only as many as fit, with the count of the
 * rest, in ANNOTATION_WHAT_MAX characters, so the cut annotationLine makes
 * never falls on ", and <n> more". The step log's plain lines list them all.
 *
 * @param {ReturnType<typeof normalizeNpm>} survivors
 * @returns {string}
 */
function gateWhat(survivors) {
  const head = `${survivors.length} HIGH/CRITICAL advisories: `;
  const tail = (shown) => (survivors.length > shown ? `, and ${survivors.length - shown} more` : "");
  const names = [];
  for (const f of survivors.slice(0, GATE_NAMED)) {
    const next = [...names, named(f)];
    if ((head + next.join(", ") + tail(next.length)).length > ANNOTATION_WHAT_MAX) break;
    names.push(named(f));
  }
  return head + names.join(", ") + tail(names.length);
}

/**
 * The gate's plain line for one surviving advisory: its id and package, its
 * severity and title, and what fixes it, the version npm names (`fixed`), a
 * fix npm can find within the ranges, or none yet.
 *
 * @param {ReturnType<typeof normalizeNpm>[number]} f
 * @returns {string}
 */
function survivorLine(f) {
  const remedy = f.fixed ? `upgrade to ${logSafe(f.fixed)}` : f.fix_available ? "a fixed version exists (npm audit fix finds it)" : "no fixed version yet";
  return `  - ${named(f)}, ${logSafe(f.severity, 20)}${f.title ? `: ${logSafe(f.title)}` : ""}; ${remedy}`;
}

if (isMainModule(import.meta.url)) {
  const [mode, ...args] = process.argv.slice(2);
  try {
    if (mode === "gate") {
      const [auditPath] = args;
      if (!auditPath) throw new Error(USAGE.gate);
      const findings = normalizeNpm(await readReport(auditPath));
      const ignores = (process.env.IGNORES ?? "").split(/\s+/).filter(Boolean);
      const survivors = gateSurvivors(findings, ignores);
      const ignored = findings.filter((f) => ignores.includes(f.id)).map((f) => f.id);
      if (ignored.length) console.log(`ignores honored: ${ignored.join(", ")}`);
      if (survivors.length) {
        console.error(`dependency gate: ${survivors.length} HIGH/CRITICAL advisories survive the ignores:`);
        for (const f of survivors) console.error(survivorLine(f));
        annotate({
          title: "Dependency gate",
          file: "app/package-lock.json",
          what: gateWhat(survivors),
          fix: "upgrade each package past its advisory (the step log names the fixed versions), or ask a platform " +
            "admin for safety.ignore.deps.<advisory id> if one does not apply",
        });
        process.exitCode = 1;
      } else {
        console.log(`dependency gate clean (${findings.length} total advisories below floor or ignored)`);
      }
    } else if (mode === "post") {
      const [lane, base, app, deploymentId, reportPath, token] = args;
      if (!lane || !base || !app || !deploymentId || !reportPath || !token) throw new Error(USAGE.post);
      if (!Object.hasOwn(NORMALIZERS, lane)) throw new Error(`unknown lane ${JSON.stringify(logSafe(lane, 40))}: use "trivy" or "npm"`);
      const deploymentIdNum = parseIntegerArg("deploymentId", deploymentId);
      const findings = NORMALIZERS[lane](await readReport(reportPath));
      const result = await postFindings({ base, token, lane, app, deploymentId: deploymentIdNum, findings });
      console.log(`${LANES[lane].label}: ${logSafe(JSON.stringify(result), Infinity)}`);
    } else if (mode === "no-deps") {
      const [base, app, deploymentId, token] = args;
      if (!base || !app || !deploymentId || !token) throw new Error(USAGE["no-deps"]);
      const deploymentIdNum = parseIntegerArg("deploymentId", deploymentId);
      const result = await postFindings({ base, token, lane: "npm", app, deploymentId: deploymentIdNum, findings: [] });
      console.log(`${LANES.npm.label}: ${logSafe(JSON.stringify(result), Infinity)}`);
    } else if (mode === "post-failed") {
      const [lane, base, app, reason, token] = args;
      if (!lane || !base || !app || !reason || !token) throw new Error(USAGE["post-failed"]);
      const result = await postFailure({ base, token, lane, app, reason });
      console.log(`${LANES[lane].label}: ${logSafe(JSON.stringify(result), Infinity)}`);
    } else {
      throw new Error(`unknown mode ${JSON.stringify(logSafe(mode ?? "", 40))}: use "gate", "post", "no-deps" or "post-failed"`);
    }
  } catch (err) {
    const message = String(err?.message ?? err);
    // The tenant gate's failure is the author's to see on the run page; the
    // sweep's, and any usage line, stay plain (flattened: a report's parse
    // error quotes the raw file).
    if (mode === "gate" && !message.startsWith("Usage:")) {
      annotate({ title: "Dependency gate", what: message, fix: "re-run the workflow; if it repeats, ask a platform admin" });
    } else {
      console.error(logSafe(message, Infinity));
    }
    process.exitCode = 1;
  }
}
