// The accessibility scanner's report (ci/a11y-scan.mjs, split in v0.18.16,
// CI-08): the verdict a scan's result earns under the app's policy
// (parseMode, parseIgnores and evaluate: what blocks in enforce, and what is
// the platform's and exits 3), the advisory response-header check
// (headerFindings), the step summary's Markdown (renderSummary, with cell
// and code escaping everything the app controls), and the workflow-command
// annotations, bounded per kind (annotations, every line through
// ../cli.mjs annotationLine). It reads a result and returns strings;
// ci/a11y-scan.mjs prints them.

import { annotationLine, logSafe } from "../cli.mjs";
import { APP_FAULT_STATUSES, AXE_TAGS, IMPACT_ORDER, RULE_ID_RE } from "./scan.mjs";

export const BLOCKING_IMPACTS = ["critical", "serious"];
// GitHub renders at most 10 annotations of each kind (error, warning) per
// step and drops the rest silently, in print order: a longer list used to
// lose the response-header advisories and its own overflow pointer, both
// printed last. Beside this budget, one run can print four more warnings:
// the workflow step's route-file warning before the scan, the scanner's own
// crash line (at the bottom of ci/a11y-scan.mjs), and after the scan the
// step's summary-symlink warning and its exit-status warning, whose enforce
// error replaces it (so one more error at most). The scanner therefore keeps to 6
// of each kind, and points at the step summary with a ::notice, a kind the
// findings never use. test/a11y-workflow.node.test.ts runs the step on every
// path and fails if a new line breaks the sum.
export const ANNOTATIONS_PER_KIND = 6;

/**
 * Split the policy job's space-separated ignore list, keeping only ids that
 * match the rule-id grammar (a fourth layer after write, serve and policy-job
 * filtering).
 *
 * @param {string|undefined} raw
 * @returns {Set<string>}
 */
export function parseIgnores(raw) {
  return new Set(String(raw ?? "").split(/\s+/).filter((s) => s && RULE_ID_RE.test(s)));
}

/**
 * Normalize a mode string; anything unrecognized reads as "report" (the
 * non-blocking direction, matching the policy job's fallback).
 *
 * @param {string|undefined} raw
 * @returns {"off"|"report"|"enforce"}
 */
export function parseMode(raw) {
  return raw === "enforce" || raw === "off" ? raw : "report";
}

/**
 * Decide the outcome of a scan.
 *
 * @param {{pages: Array<{route: string, status: string, violations?: Array<{id: string, impact: string|null, nodes: number}>}>, infra?: boolean, error?: string|null}} result
 * @param {"report"|"enforce"} mode
 * @param {Set<string>} ignores
 * @returns {{exitCode: number, counts: Record<string, number>, blocking: number, ignored: number, scanned: number, unscanned: number, verdict: string, landingFault: string|null}}
 */
export function evaluate(result, mode, ignores) {
  const counts = Object.fromEntries(IMPACT_ORDER.map((k) => [k, 0]));
  let blocking = 0;
  let ignored = 0;
  let scanned = 0;
  let unscanned = 0;
  for (const p of result.pages) {
    if (p.status !== "scanned") { unscanned++; continue; }
    scanned++;
    for (const v of p.violations ?? []) {
      if (ignores.has(v.id)) { ignored++; continue; }
      const impact = IMPACT_ORDER.includes(v.impact ?? "") ? v.impact : "minor";
      counts[impact]++;
      if (BLOCKING_IMPACTS.includes(impact)) blocking++;
    }
  }
  let verdict;
  let exitCode = 0;
  if (scanned === 0 && result.pages.length > 0 && !result.infra && result.pages.every((p) => p.status === "not-html")) {
    // An API-only app: nothing a person opens in a browser, so nothing to
    // check (APP-ACCESSIBILITY "Who this applies to"). Not a failure.
    verdict = "not-applicable";
  } else if (scanned === 0) {
    verdict = "did-not-run";
    // Blocks only when the APP is why nothing could be scanned; a platform-
    // side failure exits 3 (reported, never blocking).
    // Every page must be accounted for by the app (or be non-HTML): one
    // page the scanner itself failed on means coverage was decided by the
    // platform, not the app, so the run warns instead.
    const appFault = !result.infra && result.pages.length > 0 &&
      result.pages.every((p) => APP_FAULT_STATUSES.includes(p.status) || p.status === "not-html") &&
      result.pages.some((p) => APP_FAULT_STATUSES.includes(p.status));
    if (mode === "enforce") exitCode = appFault ? 1 : 3;
  } else if (blocking > 0) {
    verdict = "violations";
    if (mode === "enforce") exitCode = 1;
  } else {
    verdict = Object.values(counts).some((n) => n > 0) ? "minor-only" : "none-detected";
  }
  // "/" is always scanned so the route list cannot steer enforce away from
  // the landing page; that only holds if an app-caused failure on "/" is
  // itself blocking, whatever the other routes did.
  const landing = result.pages.find((p) => p.route === "/");
  // A non-HTML "/" counts too once another route proved the app serves HTML
  // (an API-only app, with no HTML anywhere, stays "not applicable").
  const landingDodged = landing && (APP_FAULT_STATUSES.includes(landing.status) || (landing.status === "not-html" && scanned > 0));
  const landingFault = landingDodged && !result.infra ? (landing.reason ?? landing.status) : null;
  if (landingFault && mode === "enforce") exitCode = 1;
  return { exitCode, counts, blocking, ignored, scanned, unscanned, verdict, landingFault };
}

/**
 * Advisory response-header findings for an HTML page served by the app.
 * HSTS is deliberately not checked: the front door owns it (APP-SECURITY §1) and
 * a localhost response never carries it.
 *
 * @param {Record<string, string>} headers - response headers (any case)
 * @returns {Array<{header: string, ok: boolean, note: string}>}
 */
export function headerFindings(headers) {
  const h = Object.fromEntries(Object.entries(headers ?? {}).map(([k, v]) => [k.toLowerCase(), String(v)]));
  const csp = h["content-security-policy"] ?? "";
  const out = [];
  if (csp) {
    out.push({ header: "Content-Security-Policy", ok: true, note: "present" });
  } else if (h["content-security-policy-report-only"]) {
    out.push({ header: "Content-Security-Policy", ok: false, note: "report-only policy present; not yet enforced" });
  } else {
    out.push({ header: "Content-Security-Policy", ok: false, note: "missing; see APP-SECURITY §9 for a starting policy" });
  }
  out.push(/^\s*nosniff\s*$/i.test(h["x-content-type-options"] ?? "")
    ? { header: "X-Content-Type-Options", ok: true, note: "nosniff" }
    : { header: "X-Content-Type-Options", ok: false, note: "missing or not nosniff" });
  out.push(framingFinding(csp, h["x-frame-options"] ?? ""));
  out.push(h["referrer-policy"]
    ? { header: "Referrer-Policy", ok: true, note: logSafe(h["referrer-policy"], 60) }
    : { header: "Referrer-Policy", ok: false, note: "missing (browser default applies)" });
  if ((h["access-control-allow-origin"] ?? "").trim() === "*") {
    out.push({ header: "Access-Control-Allow-Origin", ok: false, note: "* on an authenticated page: any origin may read responses" });
  }
  return out;
}

/**
 * Framing control. A CSP frame-ancestors directive takes precedence over
 * X-Frame-Options in current browsers, so when present it alone decides; a
 * wildcard or scheme-only source ("*", "https:") restricts nothing.
 */
function framingFinding(csp, xfo) {
  const header = "Framing (frame-ancestors / X-Frame-Options)";
  const m = /(?:^|;)\s*frame-ancestors(?:\s+([^;]*))?/i.exec(csp);
  if (m) {
    const sources = (m[1] ?? "").trim().split(/\s+/).filter(Boolean);
    if (sources.length === 0) return { header, ok: false, note: "frame-ancestors lists no sources; write 'none' explicitly" };
    const open = sources.some((x) => x === "*" || /^[a-z][a-z0-9+.-]*:$/i.test(x));
    return open
      ? { header, ok: false, note: "frame-ancestors allows any site (wildcard or scheme-only source)" }
      : { header, ok: true, note: "restricted by frame-ancestors" };
  }
  if (/^\s*(deny|sameorigin)\s*$/i.test(xfo)) return { header, ok: true, note: "restricted by X-Frame-Options" };
  return { header, ok: false, note: "unrestricted: any site can frame this page (clickjacking)" };
}

/** Markdown-table-safe cell: flatten control characters, escape pipes and angle brackets. */
export function cell(s, n = 120) {
  // Everything but plain letters, digits, space and a few inert punctuation
  // marks becomes a numeric character reference, which GitHub renders as the
  // literal character: no table break (|), HTML, link, image, emphasis,
  // code span or autolink can come out of app-controlled text. "." is
  // encoded too, since GitHub autolinks a bare www.example.com/x.
  return logSafe(s, n).replace(/[^A-Za-z0-9 ,;=?\/-]/g, (c) => `&#${c.codePointAt(0)};`);
}

/** Text for inside a markdown code span in a table (entities do not decode there). */
export function code(s, n = 80) {
  return logSafe(s, n).replace(/`/g, "'").replace(/\|/g, "\\|");
}

/**
 * Render the GitHub step summary.
 *
 * @param {object} args
 * @returns {string}
 */
export function renderSummary({ app, mode, result, outcome, headers, routesWarning, ignores }) {
  const L = [];
  const label = mode === "enforce" ? "enforce" : "report only";
  L.push(`### Accessibility report (axe-core ${cell(result.axeVersion ?? "?", 20)}, ${label})`);
  L.push("");
  if (app) L.push(`App: \`${code(app, 40)}\`. Rules: WCAG 2.0/2.1/2.2 A and AA (\`${AXE_TAGS.join(" ")}\`).`);
  if (outcome.verdict === "not-applicable") {
    L.push("");
    L.push("No route answered HTML, so there was no browser UI to check (an API-only app). " +
      "If this app does serve pages, list them in `app/inno-a11y.json`.");
  } else if (outcome.verdict === "did-not-run") {
    L.push("");
    L.push("**:warning: The accessibility scan did not run on any page.** This is not a clean result." +
      (result.error ? ` Reason: ${cell(result.error, 200)}` : ""));
  } else {
    const c = outcome.counts;
    L.push("");
    L.push(`| critical | serious | moderate | minor | ignored by policy |`);
    L.push(`|---:|---:|---:|---:|---:|`);
    L.push(`| ${c.critical} | ${c.serious} | ${c.moderate} | ${c.minor} | ${outcome.ignored} |`);
  }
  if (routesWarning) { L.push(""); L.push(`:warning: ${cell(routesWarning, 200)}`); }
  if (outcome.landingFault && outcome.verdict !== "did-not-run") {
    L.push("");
    L.push(`**:warning: The landing page \`/\` could not be scanned** (${cell(outcome.landingFault, 120)}). ` +
      "It is always checked; clean results on other routes do not make up for it" +
      (mode === "enforce" ? ", so this fails the deploy in enforce mode." : "."));
  }
  L.push("");
  L.push("| Route | Result | Violations (rule: elements) |");
  L.push("|---|---|---|");
  for (const p of result.pages) {
    const vs = (p.violations ?? []).map((v) => `${cell(v.id, 40)} (${cell(v.impact ?? "?", 10)}${ignores.has(v.id) ? ", ignored" : ""}): ${Number(v.nodes) || 0}`);
    const status = p.status === "scanned" ? "scanned" : `not scanned: ${cell(p.reason ?? p.status, 80)}`;
    const found = p.status !== "scanned" ? "n/a" : vs.length ? vs.join("<br>") : "none detected";
    L.push(`| \`${code(p.route, 80)}\` | ${status} | ${found} |`);
  }
  if (headers && headers.length) {
    L.push("");
    L.push("#### Response headers (advisory, never blocks)");
    L.push("");
    L.push("| Header | | Note |");
    L.push("|---|---|---|");
    for (const f of headers) L.push(`| ${cell(f.header)} | ${f.ok ? ":white_check_mark:" : ":warning:"} | ${cell(f.note)} |`);
  }
  L.push("");
  L.push("Automated rules catch only part of WCAG: keyboard operation, focus order, meaningful text alternatives and " +
    "error handling need a person. A clean report means *no detected violations on these pages*, not \"accessible\" " +
    "or \"compliant\". Guidance: the platform MCP tool `get_app_accessibility` (docs/APP-ACCESSIBILITY.md).");
  if (mode !== "enforce") {
    L.push("");
    L.push("Report mode: these findings do not block the deploy (config store `safety.a11y.mode`).");
  }
  return L.join("\n") + "\n";
}

/**
 * Workflow-command annotations, at most ANNOTATIONS_PER_KIND of each kind, in
 * priority order: the verdict-level lines, then the response-header
 * advisories and the unscanned pages (each folded into one line when there
 * is more than one, so they always fit), then the findings, most severe
 * first, while their kind has room; a notice counts the findings that did
 * not fit. Every line is ci/cli.mjs's annotationLine (R7-5), which flattens
 * and bounds every value, escapes the title as a property and the message's
 * "%": rule ids and help text come from axe, but routes and selectors come
 * from the app and its DOM, and a newline would end the command and forge a
 * second one. The pieces keep their own tighter bounds as well.
 *
 * @returns {string[]}
 */
export function annotations({ mode, result, outcome, ignores, routesWarning,
  headers = /** @type {Array<{header: string, ok: boolean, note: string}>} */ ([]) }) {
  const out = [];
  const room = { error: ANNOTATIONS_PER_KIND, warning: ANNOTATIONS_PER_KIND };
  const emit = (level, fields) => {
    if (level in room) {
      if (room[level] === 0) return false;
      room[level]--;
    }
    out.push(annotationLine({ level, ...fields }));
    return true;
  };
  if (outcome.verdict === "did-not-run") {
    const level = outcome.exitCode === 1 ? "error" : "warning";
    const why = outcome.exitCode === 3 ? " (platform-side; not blocking)" : "";
    emit(level, { title: "Accessibility scan did not run", what: logSafe(result.error ?? "no route could be scanned", 300),
      fix: `this is not a clean result${why}` });
  }
  if (outcome.landingFault && outcome.verdict !== "did-not-run") {
    const level = outcome.exitCode === 1 ? "error" : "warning";
    emit(level, { title: "Accessibility: landing page not scanned", what: `/ could not be scanned (${logSafe(outcome.landingFault, 120)})`,
      fix: "the landing page is always checked, so other clean routes do not make up for it" });
  }
  if (outcome.verdict === "not-applicable") {
    emit("notice", { title: "Accessibility scan not applicable", what: "no route answered HTML (an API-only app); nothing to check" });
  }
  if (routesWarning) emit("warning", { title: "Accessibility routes", what: logSafe(routesWarning, 300) });
  const bad = headers.filter((f) => !f.ok);
  if (bad.length === 1) {
    emit("warning", { title: `Response header (advisory): ${logSafe(bad[0].header, 60)}`, what: logSafe(bad[0].note, 160) });
  } else if (bad.length > 1) {
    emit("warning", { title: "Response headers (advisory)",
      what: `${bad.length} to review: ${bad.map((f) => `${logSafe(f.header, 60)}: ${logSafe(f.note, 100)}`).join("; ")}` });
  }
  const unscanned = result.pages.filter((p) => p.status !== "scanned");
  if (unscanned.length === 1) {
    const [p] = unscanned;
    emit("warning", { title: "Accessibility: page not scanned", what: `${logSafe(p.route, 80)}: ${logSafe(p.reason ?? p.status, 160)}` });
  } else if (unscanned.length > 1) {
    emit("warning", { title: `Accessibility: ${unscanned.length} pages not scanned`,
      what: unscanned.map((p) => `${logSafe(p.route, 80)} (${logSafe(p.reason ?? p.status, 100)})`).join("; ") });
  }
  const rows = [];
  for (const p of result.pages) {
    if (p.status !== "scanned") continue;
    for (const v of p.violations ?? []) {
      if (ignores.has(v.id)) continue;
      const rank = IMPACT_ORDER.indexOf(v.impact ?? "minor");
      rows.push({ p, v, rank: rank === -1 ? IMPACT_ORDER.length - 1 : rank });
    }
  }
  rows.sort((a, b) => a.rank - b.rank);
  let dropped = 0;
  for (const { p, v } of rows) {
    const blocking = BLOCKING_IMPACTS.includes(v.impact ?? "");
    const level = mode === "enforce" && blocking ? "error" : "warning";
    const where = v.targets && v.targets.length ? ` e.g. ${logSafe(v.targets[0], 80)}` : "";
    if (!emit(level, { title: `Accessibility (${logSafe(v.impact ?? "unknown", 10)}): ${logSafe(v.id, 40)}`,
      what: `${logSafe(p.route, 80)}: ${logSafe(v.help, 140)}; ${Number(v.nodes) || 0} element(s)${where}. ${logSafe(v.helpUrl ?? "", 120)}` })) dropped++;
  }
  if (dropped > 0) emit("notice", { title: "Accessibility", what: `${dropped} more finding(s) in the step summary` });
  return out;
}
