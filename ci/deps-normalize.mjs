#!/usr/bin/env node
// Normalizes `npm audit --json` output to the platform's SweepFinding shape,
// in two roles:
//   gate <auditJson>                          — CI deploy gate: exit 1 if any
//     HIGH/CRITICAL advisory survives the $IGNORES list (space-separated ids).
//     This is what lets safety.ignore.deps.* apply to npm the way it already
//     applies to pip-audit — without it, a sweep-side ignore still bricks
//     every future deploy.
//   post <base> <app> <deploymentId> <auditJson> <token> — safety-sweep lane:
//     POST ALL normalized findings to /sweep/deps-results; the Worker is the
//     policy brain (floor + ignores) exactly as with trivy results.
// A top-level `error` in the audit JSON means npm audit DID NOT RUN — that is
// a hard failure in both roles, never "clean".

import { readFile } from "node:fs/promises";
import { brokerPost } from "./broker-post.mjs";
import { isMainModule, logSafe, parseIntegerArg } from "./cli.mjs";

const RANK = { CRITICAL: 0, HIGH: 1, MODERATE: 2, LOW: 3, INFO: 4 };

/**
 * Flatten `npm audit --json` (auditReportVersion 2) into SweepFinding rows —
 * one per advisory id (string vias are transitive refs, skipped), severity
 * uppercased, CRITICAL-first, capped at 200. Throws when the report carries a
 * top-level `error` (npm audit did not run — never "clean").
 *
 * @param {any} audit - parsed `npm audit --json` output
 * @returns {Array<{id: string, pkg?: string, fixed?: string, fix_available: boolean, severity: string, title?: string, class: string, type: string}>}
 */
export function normalize(audit) {
  if (audit && typeof audit === "object" && audit.error) {
    const e = audit.error;
    throw new Error(`npm audit did not run: ${e.code ?? ""} ${e.summary ?? ""}`.trim());
  }
  const byId = new Map();
  for (const v of Object.values(audit?.vulnerabilities ?? {})) {
    for (const via of v.via ?? []) {
      if (typeof via !== "object" || via === null) continue; // string vias are transitive refs
      const tail = typeof via.url === "string" ? via.url.split("/").pop() : "";
      const id = tail && tail.startsWith("GHSA-") ? tail : String(via.source ?? "");
      if (!id || byId.has(id)) continue;
      const fix = v.fixAvailable;
      byId.set(id, {
        id,
        pkg: typeof via.name === "string" ? via.name : undefined,
        fixed: fix && typeof fix === "object" ? `${fix.name}@${fix.version}` : undefined,
        // npm's fixAvailable is `true`, `false`, or an object (fix pinned to
        // a specific top-level version) — collapse to a plain boolean. A
        // MISSING key (fix === undefined) reads as fixable too, matching
        // remediationClass's absent-means-fixable policy (src/advisory.ts).
        fix_available: fix !== false,
        severity: String(via.severity ?? v.severity ?? "").toUpperCase(),
        title: typeof via.title === "string" ? via.title.slice(0, 120) : undefined,
        // Lane marker for remediation advice (src/advisory.ts): everything
        // npm audit reports is an app dependency.
        class: "lang-pkgs",
        type: "npm",
      });
    }
  }
  return [...byId.values()]
    .sort((a, b) => (RANK[a.severity] ?? 9) - (RANK[b.severity] ?? 9))
    .slice(0, 200);
}

/**
 * The deploy gate's verdict filter: HIGH/CRITICAL advisories not ignored.
 *
 * @param {ReturnType<typeof normalize>} findings
 * @param {string[]} ignores - advisory ids from safety.ignore.deps.*
 * @returns {ReturnType<typeof normalize>}
 */
export function gateSurvivors(findings, ignores) {
  return findings.filter((f) =>
    (f.severity === "HIGH" || f.severity === "CRITICAL") && !ignores.includes(f.id));
}

/**
 * POST {app, deployment_id, findings} to `${base}/sweep/deps-results`, the
 * deps lane's twin of sweep-post.mjs's postResults (same body, different
 * path), exported so the POST is unit-testable the way the trivy lane's is.
 *
 * @param {string} base - broker base URL
 * @param {string} token - GitHub Actions OIDC token (sweep audience)
 * @param {string} app
 * @param {number} deploymentId
 * @param {ReturnType<typeof normalize>} findings
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} [fetcher]
 *   - injectable for testing; defaults to global fetch
 * @returns {Promise<any>} the parsed JSON response body (e.g. { recorded } or { stale })
 */
export async function postDepsResults(base, token, app, deploymentId, findings, fetcher = fetch) {
  return brokerPost(
    { base, path: "/sweep/deps-results", label: "deps-results", token, body: { app, deployment_id: deploymentId, findings } },
    fetcher,
  );
}

if (isMainModule(import.meta.url)) {
  try {
    const [mode, ...args] = process.argv.slice(2);
    if (mode === "gate") {
      const [auditPath] = args;
      if (!auditPath) throw new Error("Usage: deps-normalize.mjs gate <auditJson>  (env IGNORES = space-separated ids)");
      const findings = normalize(JSON.parse(await readFile(auditPath, "utf8")));
      const ignores = (process.env.IGNORES ?? "").split(/\s+/).filter(Boolean);
      const survivors = gateSurvivors(findings, ignores);
      const ignored = findings.filter((f) => ignores.includes(f.id)).map((f) => f.id);
      if (ignored.length) console.log(`ignores honored: ${ignored.join(", ")}`);
      if (survivors.length) {
        // logSafe on the id and the package name: both are fields of `npm
        // audit` output, which reports whatever the app's own dependency tree
        // named, and a newline inside a workflow command ends it and forges a
        // clean second command line in the run's log. Same class
        // ci/deploy-finalize.mjs documents for the declaration file.
        // console.error is the stream this line has always used; leave it
        // there (see deploy-finalize.mjs on why streams are not fungible).
        console.error(`::error title=Dependency gate::${survivors.length} HIGH/CRITICAL advisories: ` +
          survivors.map((f) => `${logSafe(f.id)}${f.pkg ? ` (${logSafe(f.pkg)})` : ""}`).join(", "));
        process.exitCode = 1;
      } else {
        console.log(`dependency gate clean (${findings.length} total advisories below floor or ignored)`);
      }
    } else if (mode === "post") {
      const [base, app, deploymentId, auditPath, token] = args;
      if (!base || !app || !deploymentId || !auditPath || !token) {
        throw new Error("Usage: deps-normalize.mjs post <base> <app> <deploymentId> <auditJson> <token>");
      }
      const deploymentIdNum = parseIntegerArg("deploymentId", deploymentId);
      const findings = normalize(JSON.parse(await readFile(auditPath, "utf8")));
      const result = await postDepsResults(base, token, app, deploymentIdNum, findings);
      console.log(`deps-results: ${JSON.stringify(result)}`);
    } else {
      throw new Error(`unknown mode ${JSON.stringify(mode)} — use "gate" or "post"`);
    }
  } catch (err) {
    console.error(String(err?.message ?? err));
    process.exitCode = 1;
  }
}
