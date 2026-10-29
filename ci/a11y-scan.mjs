#!/usr/bin/env node
// Accessibility + response-header REPORT for a container app's built image
// (contract §3 and R8; guidance in docs/APP-ACCESSIBILITY.md).
//
// The container job's smoke test already runs the exact image that will
// deploy, on the runner, with no Cloudflare Access in front of it. This script
// points a headless Chromium at that container, sends the headers the gateway
// would stamp (R3; see identityHeaders) to the app's own origin only, runs
// axe-core on each route, and reports:
//   - axe violations under the WCAG 2.0/2.1/2.2 A + AA tags, by impact;
//   - which routes were scanned and which could not be (coverage);
//   - an advisory response-header check (CSP, nosniff, framing, referrer
//     policy, wildcard CORS) on the first scanned page.
//
// Policy (config store safety.a11y.mode, served by /ci/policy):
//   off      the workflow never calls this script.
//   report   (default) findings are annotations + a step summary; exit 0
//            always, including when the scan itself could not run (that is
//            reported loudly as "did not run", never as a clean result).
//   enforce  exit 1 when any critical/serious violation remains after the
//            platform-managed ignores (safety.ignore.a11y.<rule>), or when no
//            route could be scanned because of the APP (a 4xx, blank page,
//            redirected away, never loaded): no evidence is not a pass. A
//            failure on the platform's side (no browser, no axe-core, the
//            app not answering /healthz again after the smoke test passed,
//            a 5xx from an app CI runs without its storage) exits 3, which
//            the workflow reports loudly and never blocks on.
// The header check never fails a run in any mode.
//
// "/" is always scanned; app/inno-a11y.json can only ADD routes, so an author
// cannot steer enforce mode away from the landing page.
//
// What this is not: a WCAG conformance test. Automated rules find a minority
// of real failures (keyboard operation, focus order, meaningful alt text and
// most of "is this usable" need a person). The summary says so every time.
//
// Usage:
//   node ci/a11y-scan.mjs --base <url> --axe <axe.min.js> [--app <name>]
//     [--mode report|enforce] [--ignore "<rule ids, space-separated>"]
//     [--routes <inno-a11y.json>] [--summary <file>] [--json <file>]
//     [--chrome <binary>] [--wait-healthz <seconds>] [--instance <instance.json>]
//
// The synthetic user's group is built from the instance's group prefix, read
// from --instance <path>, else INNO_INSTANCE_JSON (the JSON itself, not a
// path), else the ci/instance.json beside this script (ci/cli.mjs
// loadInstanceData). Tenant CI runs the scanner under `docker run`, which
// passes it no environment, and mounts ci/ into its container whole, so the
// default is the one it uses.
//
// Zero npm dependencies (node builtins + local cli.mjs), like every ci/ script:
// it drives Chromium over the DevTools protocol on --remote-debugging-pipe, so
// the only third-party code is the browser in the digest-pinned Playwright
// image and the axe-core file the workflow fetches and verifies against its
// published sha512 integrity before calling this.

import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isMainModule, loadInstanceData, logSafe } from "./cli.mjs";

export const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];
export const BLOCKING_IMPACTS = ["critical", "serious"];
export const IMPACT_ORDER = ["critical", "serious", "moderate", "minor"];
export const MAX_ROUTES = 10;
export const SCAN_USER = "a11y-scan@ci.invalid";
const NAV_TIMEOUT_MS = 20_000;
const IDLE_QUIET_MS = 500;
const IDLE_MAX_MS = 8_000;
const AXE_TIMEOUT_MS = 60_000;
// GitHub renders at most 10 annotations of each kind (error, warning) per
// step and drops the rest silently, in print order: a longer list used to
// lose the response-header advisories and its own overflow pointer, both
// printed last. Beside this budget, one run can print four more warnings:
// the workflow step's route-file warning before the scan, this script's own
// crash line (at the bottom of this file), and after the scan the step's
// summary-symlink warning and its exit-status warning, whose enforce error
// replaces it (so one more error at most). This script therefore keeps to 6
// of each kind, and points at the step summary with a ::notice, a kind the
// findings never use. test/a11y-workflow.node.test.ts runs the step on every
// path and fails if a new line breaks the sum.
export const ANNOTATIONS_PER_KIND = 6;
// The whole scan's wall-clock budget, well inside the hard `timeout` the
// workflow puts on the scanner's docker run (budget, /healthz wait and 60 s
// of slack), so a slow app is reported ("time budget") rather than killed.
export const SCAN_BUDGET_MS = 5 * 60_000;
// Same grammar the policy job filters ignore ids through.
const RULE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
// A path on the app's own origin: leading "/", not "//" (protocol-relative),
// no backslash, whitespace or control characters, bounded length.
const ROUTE_RE = /^\/(?!\/)[A-Za-z0-9._~!$&'()*+,;=:@%\/?#-]*$/;

// --- Pure helpers (unit-tested in test/a11y-scan.node.test.ts) --------------

/**
 * Parse the optional author-owned app/inno-a11y.json: {"routes": ["/", ...]}.
 * Refused WHOLE when malformed (the scan then covers "/" and says why), the
 * same all-or-nothing rule inno-variables.json follows. Never throws.
 *
 * @param {string|null|undefined} text - file contents, or null when absent
 * @returns {{routes: string[], warning: string|null}}
 */
export function parseRoutes(text) {
  const fallback = (warning) => ({ routes: ["/"], warning });
  const r = parseRouteList(text);
  if (r.warning) return fallback(r.warning);
  // "/" is always first; the file adds up to MAX_ROUTES more.
  const routes = ["/", ...r.routes.filter((x) => x !== "/")];
  return { routes, warning: null };
}

function parseRouteList(text) {
  const fallback = (warning) => ({ routes: [], warning });
  if (text === null || text === undefined) return fallback(null);
  let doc;
  try {
    doc = JSON.parse(String(text));
  } catch {
    return fallback("app/inno-a11y.json is not valid JSON; scanned / only");
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc) || !Array.isArray(doc.routes)) {
    return fallback('app/inno-a11y.json must be an object with a "routes" array; scanned / only');
  }
  // "/" is always scanned, so listing it costs nothing against the limit.
  const extra = doc.routes.filter((r) => r !== "/");
  if (extra.length > MAX_ROUTES) {
    return fallback(`app/inno-a11y.json lists ${extra.length} routes besides /; the limit is ${MAX_ROUTES}; scanned / only`);
  }
  const seen = new Set();
  for (const r of doc.routes) {
    if (typeof r !== "string" || r.length > 200 || !ROUTE_RE.test(r)) {
      return fallback(`app/inno-a11y.json route ${JSON.stringify(logSafe(r, 60))} is not a same-origin path like "/about"; scanned / only`);
    }
    seen.add(r);
  }
  return { routes: [...seen], warning: null };
}

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
 * The headers the gateway owns under R3, as the scan sends them: a synthetic
 * member of the app's users group (<groupPrefix><app>-users, the gateway's
 * and src/naming.ts oktaGroupName's formula), and the forwarded host and
 * proto of --base. Those two are what is true on the runner (production
 * sends the app's hostname and https); APP-CONTRACT tells apps to build
 * links from them, and an https proto here would send an app's own
 * redirects off the scanned origin. Never throws, so scan() can keep its
 * promise of a result. main() never scans without a group prefix (it reports
 * unreadable instance data as "did not run"), so no group is sent only when
 * no app is named.
 *
 * @param {{base: string, app?: string, groupPrefix?: string}} args
 * @returns {Array<{name: string, value: string}>}
 */
export function identityHeaders({ base, app, groupPrefix }) {
  let host = "";
  let proto = "";
  try {
    const u = new URL(base);
    host = u.host;
    proto = u.protocol.replace(/:$/, "");
  } catch { /* no usable --base: the scan then fails as a whole, platform-side */ }
  return [
    { name: "X-Forwarded-User", value: SCAN_USER },
    { name: "X-Forwarded-Email", value: SCAN_USER },
    { name: "X-Forwarded-Groups", value: app && groupPrefix ? `${groupPrefix}${app}-users` : "" },
    { name: "X-Forwarded-Host", value: host },
    { name: "X-Forwarded-Proto", value: proto },
  ];
}

/**
 * A same-origin request's headers with the identity headers set: any copy
 * the page sent of one of them (any case) is dropped first, so the app sees
 * exactly what the gateway would stamp, never what page script supplied.
 *
 * @param {Record<string, unknown>|undefined} headers - the request's headers
 * @param {Array<{name: string, value: string}>} identity
 * @returns {Array<{name: string, value: string}>}
 */
export function withIdentity(headers, identity) {
  const ours = new Set(identity.map((h) => h.name.toLowerCase()));
  const kept = Object.entries(headers ?? {}).filter(([name]) => !ours.has(name.toLowerCase()));
  return [...kept.map(([name, value]) => ({ name, value: String(value) })), ...identity];
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
 * HSTS is deliberately not checked: the gateway owns it (APP-SECURITY §1) and
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
 * first, while their kind has room; a ::notice counts the findings that did
 * not fit. Every interpolated value passes through logSafe: rule ids and help
 * text come from axe, but routes and selectors come from the app and its DOM,
 * and a newline would end the command and forge a second one.
 *
 * @returns {string[]}
 */
export function annotations({ mode, result, outcome, ignores, routesWarning,
  headers = /** @type {Array<{header: string, ok: boolean, note: string}>} */ ([]) }) {
  const out = [];
  const room = { error: ANNOTATIONS_PER_KIND, warning: ANNOTATIONS_PER_KIND };
  const emit = (kind, rest) => {
    if (kind in room) {
      if (room[kind] === 0) return false;
      room[kind]--;
    }
    out.push(`::${kind} ${rest}`);
    return true;
  };
  if (outcome.verdict === "did-not-run") {
    const kind = outcome.exitCode === 1 ? "error" : "warning";
    const why = outcome.exitCode === 3 ? " (platform-side; not blocking)" : "";
    emit(kind, `title=Accessibility scan did not run::${logSafe(result.error ?? "no route could be scanned", 300)}; this is not a clean result${why}`);
  }
  if (outcome.landingFault && outcome.verdict !== "did-not-run") {
    const kind = outcome.exitCode === 1 ? "error" : "warning";
    emit(kind, `title=Accessibility: landing page not scanned::/ could not be scanned (${logSafe(outcome.landingFault, 120)}); ` +
      "the landing page is always checked, so other clean routes do not make up for it");
  }
  if (outcome.verdict === "not-applicable") {
    emit("notice", "title=Accessibility scan not applicable::no route answered HTML (an API-only app); nothing to check");
  }
  if (routesWarning) emit("warning", `title=Accessibility routes::${logSafe(routesWarning, 300)}`);
  const bad = headers.filter((f) => !f.ok);
  if (bad.length === 1) {
    emit("warning", `title=Response header (advisory): ${logSafe(bad[0].header, 60)}::${logSafe(bad[0].note, 160)}`);
  } else if (bad.length > 1) {
    emit("warning", `title=Response headers (advisory)::${bad.length} to review: ` +
      bad.map((f) => `${logSafe(f.header, 60)}: ${logSafe(f.note, 100)}`).join("; "));
  }
  const unscanned = result.pages.filter((p) => p.status !== "scanned");
  if (unscanned.length === 1) {
    const [p] = unscanned;
    emit("warning", `title=Accessibility: page not scanned::${logSafe(p.route, 80)}: ${logSafe(p.reason ?? p.status, 160)}`);
  } else if (unscanned.length > 1) {
    emit("warning", `title=Accessibility: ${unscanned.length} pages not scanned::` +
      unscanned.map((p) => `${logSafe(p.route, 80)} (${logSafe(p.reason ?? p.status, 100)})`).join("; "));
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
    const kind = mode === "enforce" && blocking ? "error" : "warning";
    const where = v.targets && v.targets.length ? ` e.g. ${logSafe(v.targets[0], 80)}` : "";
    if (!emit(kind, `title=Accessibility (${logSafe(v.impact ?? "unknown", 10)}): ${logSafe(v.id, 40)}::` +
      `${logSafe(p.route, 80)}: ${logSafe(v.help, 140)}; ${Number(v.nodes) || 0} element(s)${where}. ${logSafe(v.helpUrl ?? "", 120)}`)) dropped++;
  }
  if (dropped > 0) emit("notice", `title=Accessibility::${dropped} more finding(s) in the step summary`);
  // The runner decodes %25, %0D and %0A in a command's message, so a literal
  // "%0A" in a route or selector would display as a line break: escape "%".
  return out.map((line) => {
    const at = line.indexOf("::", 2);
    return at === -1 ? line : line.slice(0, at + 2) + line.slice(at + 2).replace(/%/g, "%25");
  });
}

/**
 * Locate a Chromium binary inside the Playwright image (the directory name
 * carries the browser revision and, on some builds, the CPU architecture).
 *
 * @param {string} [root]
 * @returns {string|null}
 */
export function findChrome(root = "/ms-playwright") {
  if (!existsSync(root)) return null;
  const candidates = [];
  for (const d of readdirSync(root).sort()) {
    if (d.startsWith("chromium_headless_shell-")) {
      for (const sub of safeList(join(root, d))) {
        if (!sub.startsWith("chrome-")) continue;
        candidates.push({ rank: 0, path: join(root, d, sub, "headless_shell") });
        candidates.push({ rank: 0, path: join(root, d, sub, "chrome-headless-shell") });
      }
    } else if (d.startsWith("chromium-")) {
      for (const sub of safeList(join(root, d))) {
        if (sub.startsWith("chrome-")) candidates.push({ rank: 1, path: join(root, d, sub, "chrome") });
      }
    }
  }
  candidates.sort((a, b) => a.rank - b.rank);
  const hit = candidates.find((c) => existsSync(c.path));
  return hit ? hit.path : null;
}

function safeList(dir) {
  try { return readdirSync(dir); } catch { return []; }
}

// --- DevTools protocol over a pipe ------------------------------------------

class Cdp {
  constructor(proc) {
    this.proc = proc;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Set();
    this.buf = Buffer.alloc(0);
    this.closed = false;
    proc.stdio[4].on("data", (chunk) => this.onData(chunk));
    // A browser that fails to start (ENOENT, missing libraries) or dies mid-run
    // surfaces as 'error' events; unhandled, they would crash the scanner
    // instead of producing a "did not run" report.
    proc.on("error", (e) => this.fail(e));
    proc.stdio[3].on("error", (e) => this.fail(e));
    proc.stdio[4].on("error", (e) => this.fail(e));
    proc.on("exit", () => this.fail(new Error("browser exited")));
  }

  fail(err) {
    this.closed = true;
    for (const { reject } of this.pending.values()) reject(err instanceof Error ? err : new Error(String(err)));
    this.pending.clear();
  }

  onData(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    let i;
    while ((i = this.buf.indexOf(0)) !== -1) {
      const raw = this.buf.subarray(0, i).toString("utf8");
      this.buf = this.buf.subarray(i + 1);
      let msg;
      try { msg = JSON.parse(raw); } catch { continue; }
      if (msg.id !== undefined && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(`${msg.error.message ?? "CDP error"}`));
        else resolve(msg.result ?? {});
      } else if (msg.method) {
        for (const fn of this.listeners) fn(msg);
      }
    }
  }

  send(method, params = {}, sessionId, timeoutMs = 30_000) {
    if (this.closed) return Promise.reject(new Error("browser exited"));
    const id = this.nextId++;
    const msg = { id, method, params };
    if (sessionId) msg.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(`${method} timed out`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (v) => { clearTimeout(t); resolve(v); },
        reject: (e) => { clearTimeout(t); reject(e); },
      });
      this.proc.stdio[3].write(JSON.stringify(msg) + "\0");
    });
  }

  on(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }
}

function launchChrome(binary) {
  const profile = mkdtempSync(join(tmpdir(), "a11y-profile-"));
  const proc = spawn(binary, [
    "--headless",
    "--remote-debugging-pipe",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--disable-background-networking",
    "--window-size=1280,900",
    `--user-data-dir=${profile}`,
    "about:blank",
  ], {
    stdio: ["ignore", "ignore", "pipe", "pipe", "pipe"],
    // The CI container has a read-only root: point every per-user write
    // (profile, caches, crash reports) at the throwaway profile under /tmp.
    env: { ...process.env, HOME: profile, XDG_CONFIG_HOME: profile, XDG_CACHE_HOME: profile },
  });
  proc.stderr.on("data", () => {});
  return { proc, profile };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Page statuses that are the APP's doing (a 4xx, a blank shell, a redirect
// away, a page that never finishes loading). Anything else unscanned is, or
// may be, the scanner's or the platform's, which enforce mode never blocks
// on. A navigation error (connection refused or reset, TLS, DNS) is in that
// second group: the app just answered /healthz, so a page that cannot even be
// requested most likely points at the scan environment. So is a 5xx
// ("server-error", see responseStatus).
export const APP_FAULT_STATUSES = ["http", "redirect", "blank", "timeout"];

/**
 * Classify the status of a page's (same-origin) document response. A 4xx is
 * the app's own answer ("http", blocking in enforce, on "/" above all). A 5xx
 * is not held against it: CI runs the image with nothing behind
 * http://storage.internal (the platform's storage gateway, there once
 * deployed), so a page that reads storage can fail here and work in
 * production, and blocking on it would fail an app for the scan environment.
 * It is listed as not scanned, with a warning.
 *
 * @param {number} code
 * @returns {{status: "http"|"server-error", reason: string}|null} null for a 200
 */
export function responseStatus(code) {
  if (code === 200) return null;
  if (code >= 500) return { status: "server-error", reason: `HTTP ${code} (CI runs the app without storage.internal)` };
  return { status: "http", reason: `HTTP ${code}` };
}

// What the page ships to axe is DOM; what comes back is data the page could
// have touched only through the DOM (axe runs in an isolated world), but it is
// still validated here before it reaches a verdict, a log line or a summary.
const HELP_URL_RE = /^https:\/\/dequeuniversity\.com\/[A-Za-z0-9._~\/?&=%+-]*$/;

/**
 * Validate axe's violations as returned from the browser.
 *
 * @param {unknown} raw
 * @returns {Array<{id: string, impact: string|null, help: string, helpUrl: string, nodes: number, targets: string[]}>}
 */
export function sanitizeViolations(raw) {
  if (!Array.isArray(raw)) return [];
  return raw.slice(0, 200).map((x) => {
    const o = x && typeof x === "object" ? x : {};
    const id = typeof o.id === "string" && RULE_ID_RE.test(o.id) && o.id.length <= 80 ? o.id : "unknown-rule";
    const impact = IMPACT_ORDER.includes(o.impact) ? o.impact : null;
    const nodes = Number.isInteger(o.nodes) && o.nodes >= 0 ? Math.min(o.nodes, 100000) : 1;
    const help = typeof o.help === "string" ? logSafe(o.help, 200) : "";
    const helpUrl = typeof o.helpUrl === "string" && HELP_URL_RE.test(o.helpUrl) ? o.helpUrl.slice(0, 200) : "";
    const targets = Array.isArray(o.targets) ? o.targets.filter((t) => typeof t === "string").slice(0, 3).map((t) => logSafe(t, 120)) : [];
    return { id, impact, help, helpUrl, nodes, targets };
  });
}

// Runs in the isolated world: does the page show anything a person could
// perceive or operate? An SPA root <div> plus its (failed) <script> is not
// content; text, an image, a control, a media element or an iframe is.
const RENDERED_EXPR = `(() => {
  const b = document.body;
  if (!b) return JSON.stringify({ text: 0, media: 0 });
  const media = b.querySelectorAll("img,svg,canvas,video,audio,picture,input,button,select,textarea,iframe,object,embed,a[href]").length;
  return JSON.stringify({ text: (b.innerText || "").trim().length, media });
})()`;

const AXE_RUN_EXPR = `axe.run(document, { runOnly: { type: "tag", values: ${JSON.stringify(AXE_TAGS)} }, resultTypes: ["violations"] })` +
  `.then(r => JSON.stringify({ v: r.testEngine.version, violations: r.violations.map(x => ({ id: x.id, impact: x.impact, help: x.help, helpUrl: x.helpUrl, nodes: x.nodes.length, targets: x.nodes.slice(0, 3).map(n => [].concat(n.target).join(" ")) })) }))`;

const RENDERER_CRASHED = "the page's renderer crashed (the scanner's memory or /tmp limit)";

/**
 * Scan one route in its own browser target. A renderer crash
 * (Inspector.targetCrashed) is the scanner's failure, whatever the dead page
 * looked like by then: its own memory and /tmp limits are the likely cause,
 * and left alone it reads as a page that never loaded, rendered nothing or
 * left the origin, all of which enforce holds against the app.
 *
 * @returns {Promise<{route: string, status: string, reason?: string, [k: string]: unknown}>}
 */
export async function scanRoute(cdp, base, route, axeSource, identity, deadline) {
  const watch = { crashed: false };
  const r = await visitRoute(cdp, base, route, axeSource, identity, deadline, watch);
  return watch.crashed && r.status !== "scanned" ? { route, status: "scanner-error", reason: RENDERER_CRASHED } : r;
}

async function visitRoute(cdp, base, route, axeSource, identity, deadline, watch) {
  const url = new URL(route, base).href;
  const origin = new URL(base).origin;
  const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
  const inflight = new Set();
  let lastActivity = Date.now();
  let doc = null;
  let loaded = false;
  let mainFrame = null;
  const off = cdp.on((m) => {
    if (m.sessionId !== sessionId) return;
    const p = m.params ?? {};
    switch (m.method) {
      case "Fetch.requestPaused": {
        // Identity headers go to the app's own origin ONLY (never to a CDN
        // or any third party the page loads).
        let sameOrigin = false;
        try { sameOrigin = new URL(p.request.url).origin === origin; } catch { /* opaque url */ }
        const params = { requestId: p.requestId };
        if (sameOrigin) params.headers = withIdentity(p.request.headers, identity);
        cdp.send("Fetch.continueRequest", params, sessionId).catch(() => {});
        break;
      }
      case "Network.requestWillBeSent":
        inflight.add(p.requestId); lastActivity = Date.now();
        break;
      case "Network.responseReceived":
        // The LATEST main-frame document wins: a page that navigates itself
        // elsewhere (a client-side redirect) is judged by where it ended up.
        if (p.type === "Document" && p.frameId === mainFrame) {
          doc = { status: p.response.status, headers: p.response.headers ?? {}, url: p.response.url };
        }
        break;
      case "Network.loadingFinished":
      case "Network.loadingFailed":
        inflight.delete(p.requestId); lastActivity = Date.now();
        break;
      case "Page.frameNavigated":
        if (p.frame && !p.frame.parentId) loaded = false;
        break;
      case "Page.loadEventFired":
        loaded = true;
        break;
      case "Inspector.targetCrashed":
        watch.crashed = true;
        break;
      default:
    }
  });
  // Every CDP call for the page is capped at the scan's deadline (with a
  // one-second floor), so the budget is close to a real bound; the
  // workflow's outer timeout covers a browser that stops answering at all.
  const left = (ms) => Math.max(1000, Math.min(ms, deadline - Date.now()));
  const ctxEval = async (contextId, expression, { timeoutMs = 30_000, ...params } = {}) =>
    cdp.send("Runtime.evaluate", { expression, contextId, returnByValue: true, ...params }, sessionId, left(timeoutMs));
  try {
    await cdp.send("Page.enable", {}, sessionId, left(30_000));
    // Delivers Inspector.targetCrashed. Not essential to a scan, so a browser
    // that refuses it scans on without crash detection.
    await cdp.send("Inspector.enable", {}, sessionId, left(30_000)).catch(() => {});
    const tree = await cdp.send("Page.getFrameTree", {}, sessionId, left(30_000));
    mainFrame = tree.frameTree.frame.id;
    await cdp.send("Fetch.enable", { patterns: [{ urlPattern: "*", requestStage: "Request" }] }, sessionId, left(30_000));
    await cdp.send("Network.enable", {}, sessionId, left(30_000));
    const navBudget = Math.max(1000, Math.min(NAV_TIMEOUT_MS, deadline - Date.now()));
    let nav;
    try {
      nav = await cdp.send("Page.navigate", { url }, sessionId, navBudget);
    } catch (e) {
      // No response at all inside the budget. Reported as a navigation
      // error (platform-side, never blocking): the app just passed /healthz,
      // so a hang here cannot be pinned on it with confidence.
      return { route, status: "nav-error", reason: `no response within ${Math.round(navBudget / 1000)}s (${logSafe(e && e.message ? e.message : e, 60)})` };
    }
    if (nav.errorText) return { route, status: "nav-error", reason: `navigation failed (${logSafe(nav.errorText, 80)})` };
    // Wait for load, then for a quiet network (an SPA renders after load).
    // A client-side navigation resets `loaded`, so the wait follows it.
    const loadBy = Date.now() + navBudget;
    let idleBy = 0;
    for (;;) {
      // A dead renderer never fires load: stop now rather than wait out the
      // load budget (scanRoute reports why).
      if (watch.crashed) return { route, status: "scanner-error", reason: RENDERER_CRASHED };
      if (Date.now() > deadline) return { route, status: "budget", reason: "the scan's time budget ran out" };
      if (!loaded) {
        idleBy = 0;
        if (Date.now() > loadBy) return { route, status: "timeout", reason: `page did not finish loading within ${Math.round(navBudget / 1000)}s` };
      } else {
        if (!idleBy) idleBy = Date.now() + IDLE_MAX_MS;
        if ((inflight.size === 0 && Date.now() - lastActivity >= IDLE_QUIET_MS) || Date.now() > idleBy) break;
      }
      await sleep(100);
    }
    if (!doc) return { route, status: "scanner-error", reason: "no document response observed" };
    // Origin first: a redirect off the app is judged (and its headers
    // dropped) before its status, so a third party's headers never reach the
    // header report.
    let docOrigin = null;
    try { docOrigin = new URL(doc.url).origin; } catch { /* opaque url */ }
    if (docOrigin !== origin) return { route, status: "redirect", reason: "the page ended up off the app's origin" };
    const refused = responseStatus(doc.status);
    if (refused) return { route, ...refused, headers: doc.headers };
    const ctype = String(Object.entries(doc.headers).find(([k]) => k.toLowerCase() === "content-type")?.[1] ?? "");
    if (!/^\s*(text\/html|application\/xhtml\+xml)\b/i.test(ctype)) {
      return { route, status: "not-html", reason: `non-HTML response (${logSafe(ctype.split(";")[0] || "no content-type", 60)})` };
    }
    // The scanner's own code runs in an ISOLATED WORLD: it shares the DOM with
    // the page but none of its globals or prototypes, so page script cannot
    // replace axe, patch JSON or Array, or otherwise forge the result.
    const { executionContextId: world } = await cdp.send("Page.createIsolatedWorld", { frameId: mainFrame, worldName: "inno-a11y-scan" }, sessionId, left(30_000));
    const where = await ctxEval(world, "location.href");
    let finalOrigin = null;
    try { finalOrigin = new URL(String(where.result?.value)).origin; } catch { /* not a url */ }
    if (finalOrigin !== origin) {
      return { route, status: "redirect", reason: "the page ended up off the app's origin" };
    }
    const shape = await ctxEval(world, RENDERED_EXPR);
    let rendered = { text: 0, media: 0 };
    try { rendered = JSON.parse(String(shape.result?.value)); } catch { /* treated as blank */ }
    if (!(rendered.text > 0 || rendered.media > 0)) {
      return { route, status: "blank", reason: "the page rendered no content (blank SPA shell or script error)", headers: doc.headers };
    }
    const inject = await ctxEval(world, axeSource + "\n;typeof axe");
    if (inject.exceptionDetails || inject.result?.value !== "object") {
      return { route, status: "scanner-error", reason: "axe-core could not be loaded into the page" };
    }
    const run = await ctxEval(world, AXE_RUN_EXPR, { awaitPromise: true, timeoutMs: AXE_TIMEOUT_MS });
    if (run.exceptionDetails || typeof run.result?.value !== "string") {
      return { route, status: "scanner-error", reason: "axe-core run failed on this page" };
    }
    let parsed;
    try { parsed = JSON.parse(run.result.value); } catch { return { route, status: "scanner-error", reason: "axe-core returned unreadable output" }; }
    if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.violations)) {
      return { route, status: "scanner-error", reason: "axe-core returned a malformed result" };
    }
    const axeVersion = typeof parsed.v === "string" && /^[0-9][0-9A-Za-z.+-]{0,30}$/.test(parsed.v) ? parsed.v : null;
    if (!axeVersion) return { route, status: "scanner-error", reason: "axe-core returned a malformed result (no version)" };
    // Only rule metadata, counts and CSS selectors are kept: never DOM text or
    // HTML snippets, which can carry whatever data the page rendered.
    return { route, status: "scanned", axeVersion, violations: sanitizeViolations(parsed?.violations), headers: doc.headers };
  } catch (e) {
    return { route, status: "scanner-error", reason: logSafe(e && e.message ? e.message : e, 160) };
  } finally {
    off();
    await cdp.send("Target.closeTarget", { targetId }, undefined, 5_000).catch(() => {});
  }
}

async function waitHealthz(base, seconds) {
  const deadline = Date.now() + seconds * 1000;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(new URL("/healthz", base), { signal: AbortSignal.timeout(4000) });
      if (r.status === 200) return true;
    } catch { /* not up yet */ }
    await sleep(2000);
  }
  return false;
}

/**
 * Drive the browser over every route. Never throws: a failure to start is a
 * result with no scanned pages and an error string.
 */
export async function scan({ base, routes, axeSource, app, groupPrefix, chrome, budgetMs = SCAN_BUDGET_MS }) {
  const deadline = Date.now() + budgetMs;
  const identity = identityHeaders({ base, app, groupPrefix });
  const binary = chrome || findChrome();
  if (!binary) return { pages: [], infra: true, error: "no Chromium found in the scanner image" };
  const { proc, profile } = launchChrome(binary);
  const cdp = new Cdp(proc);
  const pages = [];
  let axeVersion = null;
  try {
    await cdp.send("Browser.getVersion", {}, undefined, 15_000);
    for (const route of routes) {
      if (Date.now() > deadline) {
        pages.push({ route, status: "budget", reason: "the scan's time budget ran out" });
        continue;
      }
      const r = await scanRoute(cdp, base, route, axeSource, identity, deadline);
      if (r.axeVersion) axeVersion = r.axeVersion;
      pages.push(r);
    }
    return { pages, axeVersion, error: pages.some((p) => p.status === "scanned") ? null : (pages[0]?.reason ?? "no route scanned") };
  } catch (e) {
    return { pages, axeVersion, infra: true, error: `browser failed: ${logSafe(e && e.message ? e.message : e, 160)}` };
  } finally {
    proc.kill("SIGKILL");
    rmSync(profile, { recursive: true, force: true });
  }
}

// --- CLI --------------------------------------------------------------------

const USAGE = "Usage: node ci/a11y-scan.mjs --base <url> --axe <axe.min.js> [--app <name>] " +
  "[--mode report|enforce] [--ignore \"<rule ids, space-separated>\"] [--routes <inno-a11y.json>] " +
  "[--summary <file>] [--json <file>] [--chrome <binary>] [--wait-healthz <seconds>] [--instance <instance.json>]";
// Every flag in USAGE. Anything else is refused rather than skipped: a typo
// such as --wait-heathz would otherwise drop the setting it meant without a
// word, and an unquoted --ignore list would lose all but its first rule id.
const FLAGS = new Set(["base", "axe", "app", "mode", "ignore", "routes", "summary", "json", "chrome", "wait-healthz", "instance"]);

/**
 * Parse `--flag value` pairs (a flag followed by another flag, or by
 * nothing, reads as ""). Throws on an unknown flag or a stray argument.
 *
 * @param {string[]} argv
 * @returns {Record<string, string>}
 */
export function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--") || !FLAGS.has(a.slice(2))) throw new Error(`unknown argument ${JSON.stringify(logSafe(a, 60))}`);
    const val = argv[i + 1] !== undefined && !argv[i + 1].startsWith("--") ? argv[++i] : "";
    out[a.slice(2)] = val;
  }
  return out;
}

export async function main(argv = process.argv.slice(2)) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    // Exit 2, the usage convention: the workflow reads anything but a
    // result.json-confirmed 1 as platform-side, so a bad invocation warns
    // and never becomes the app's verdict.
    console.error(`a11y-scan: ${e instanceof Error ? e.message : String(e)}`);
    console.error(USAGE);
    return 2;
  }
  const mode = parseMode(args.mode);
  if (mode === "off") {
    console.log("a11y: safety.a11y.mode is off; no accessibility scan.");
    return 0;
  }
  const ignores = parseIgnores(args.ignore);
  let routesText = null;
  if (args.routes && existsSync(args.routes)) routesText = readFileSync(args.routes, "utf8");
  const { routes, warning: routesWarning } = parseRoutes(routesText);
  let result;
  let groupPrefix = null;
  try {
    groupPrefix = loadInstanceData({ path: args.instance || undefined }).groupPrefix;
  } catch (e) {
    // The platform's file, never the app's fault: reported, never blocking.
    // loadInstanceData says "<source>: <reason>", and the source can be a
    // long path, so the reason goes first and a cut at the bound drops the
    // tail of the path, never the reason.
    const msg = String(e instanceof Error ? e.message : e);
    const at = msg.indexOf(": ");
    const line = at < 0 ? msg : `${msg.slice(at + 2)} (${msg.slice(0, at)})`;
    result = { pages: [], infra: true, error: `the instance data could not be read: ${logSafe(line, 160)}` };
  }
  let axeSource = null;
  if (!result) {
    try {
      axeSource = readFileSync(args.axe, "utf8");
    } catch {
      result = { pages: [], infra: true, error: "axe-core was not available to the scanner" };
    }
  }
  if (!result && !args.base) result = { pages: [], infra: true, error: "no --base url" };
  if (!result && args["wait-healthz"] && !(await waitHealthz(args.base, Number(args["wait-healthz"]) || 90))) {
    // The smoke test just proved /healthz on this image, so a miss here is
    // the scan environment's problem, reported but never blocking.
    result = { pages: [], infra: true, error: "the app did not answer /healthz 200 for the scan" };
  }
  if (!result) result = await scan({ base: args.base, routes, axeSource, app: args.app, groupPrefix, chrome: args.chrome });
  const outcome = evaluate(result, mode, ignores);
  const first = result.pages.find((p) => p.headers && p.status === "scanned") ?? result.pages.find((p) => p.headers);
  const headers = first ? headerFindings(first.headers) : [];
  for (const line of annotations({ mode, result, outcome, ignores, routesWarning, headers })) console.log(line);
  const summary = renderSummary({ app: args.app, mode, result, outcome, headers, routesWarning, ignores });
  if (args.summary) writeFileSync(args.summary, summary);
  if (args.json) {
    writeFileSync(args.json, JSON.stringify({ mode, outcome, axeVersion: result.axeVersion ?? null, error: result.error ?? null,
      pages: result.pages.map(({ headers: _h, ...p }) => p), headers }, null, 2));
  }
  const c = outcome.counts;
  console.log(`a11y: ${outcome.scanned} page(s) scanned, ${outcome.unscanned} not scanned; ` +
    `critical ${c.critical}, serious ${c.serious}, moderate ${c.moderate}, minor ${c.minor}, ignored ${outcome.ignored}; ` +
    `mode ${mode}; verdict ${outcome.verdict}.`);
  return outcome.exitCode;
}

if (isMainModule(import.meta.url)) {
  // A crash is never an app verdict: Node's own exit code for an uncaught
  // error is 1, which the workflow would otherwise read as "block". (The
  // workflow also requires result.json to confirm exitCode 1 before it
  // blocks, which covers crashes before this module even loads.)
  const crashed = (e) => {
    console.log(`::warning title=Accessibility scan crashed::${logSafe(e && e.message ? e.message : e, 200)} (platform-side; not blocking)`);
    process.exit(3);
  };
  process.on("uncaughtException", crashed);
  process.on("unhandledRejection", crashed);
  main().then((code) => process.exit(code)).catch(crashed);
}
