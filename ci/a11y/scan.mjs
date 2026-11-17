// The accessibility scanner's scan (ci/a11y-scan.mjs, split in v0.18.16,
// CI-08): which routes it visits (parseRoutes) and as whom (parseIdentity,
// identityHeaders and withIdentity, the headers the front door would stamp,
// sent to the app's own origin only); how it drives each page through
// ci/a11y/cdp.mjs's browser (scanRoute: the load, a quiet network, an
// isolated world, axe-core); how it files a page it could not scan
// (APP_FAULT_STATUSES, responseStatus); and what it keeps of axe's answer
// (sanitizeViolations). scan() never throws: a browser that cannot start is
// a result with no scanned page. What a result means, and how it is said, is
// ci/a11y/report.mjs's.

import { logSafe } from "../cli.mjs";
import { Cdp, closeBrowser, findChrome, launchChrome, sleep } from "./cdp.mjs";

export const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];
export const IMPACT_ORDER = ["critical", "serious", "moderate", "minor"];
export const MAX_ROUTES = 10;
export const SCAN_USER = "a11y-scan@ci.invalid";
// The synthetic person's subject (X-Forwarded-Subject). APP-CONTRACT R3 tells
// apps to key per-person data on the subject, so a page that does renders as
// it does for a signed-in person rather than for a caller with none.
export const SCAN_SUBJECT = "a11y-scan";
const NAV_TIMEOUT_MS = 20_000;
const IDLE_QUIET_MS = 500;
const IDLE_MAX_MS = 8_000;
const AXE_TIMEOUT_MS = 60_000;
// The whole scan's wall-clock budget, well inside the hard `timeout` the
// workflow puts on the scanner's docker run (budget, /healthz wait and 60 s
// of slack), so a slow app is reported ("time budget") rather than killed.
export const SCAN_BUDGET_MS = 5 * 60_000;
// Same grammar the policy job filters ignore ids through.
export const RULE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
// A path on the app's own origin: leading "/", not "//" (protocol-relative),
// no backslash, whitespace or control characters, bounded length.
const ROUTE_RE = /^\/(?!\/)[A-Za-z0-9._~!$&'()*+,;=:@%\/?#-]*$/;

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
 * Normalize the app's identity (--identity, from /ci/policy): only
 * "anonymous" reads as anonymous, and anything else as "identity-aware",
 * the scan every app had before identity existed (the policy job's
 * fallback too).
 *
 * @param {string|undefined} raw
 * @returns {"identity-aware"|"anonymous"}
 */
export function parseIdentity(raw) {
  return raw === "anonymous" ? "anonymous" : "identity-aware";
}

/**
 * The headers the front door owns under R3, as the scan sends them: a
 * synthetic member of the app's users group (<groupPrefix><app>-users,
 * src/naming.ts usersGroupName's formula) with a synthetic subject, and the
 * forwarded host and proto of --base. Those two are what is true on the runner (production
 * sends the app's hostname and https); APP-CONTRACT tells apps to build
 * links from them, and an https proto here would send an app's own
 * redirects off the scanned origin. Never throws, so scan() can keep its
 * promise of a result. ci/a11y-scan.mjs's main() never scans without a group prefix (it reports
 * unreadable instance data as "did not run"), so no group is sent only when
 * no app is named. For an anonymous app the four identity headers are sent
 * present and empty, as the front door serves that app every caller
 * (front-door/identity.ts NO_IDENTITY), so its pages are checked as a caller
 * with no identity sees them; the host and proto are the same.
 *
 * @param {{base: string, app?: string, groupPrefix?: string, anonymous?: boolean}} args
 * @returns {Array<{name: string, value: string}>}
 */
export function identityHeaders({ base, app, groupPrefix, anonymous = false }) {
  let host = "";
  let proto = "";
  try {
    const u = new URL(base);
    host = u.host;
    proto = u.protocol.replace(/:$/, "");
  } catch { /* no usable --base: the scan then fails as a whole, platform-side */ }
  return [
    { name: "X-Forwarded-User", value: anonymous ? "" : SCAN_USER },
    { name: "X-Forwarded-Email", value: anonymous ? "" : SCAN_USER },
    { name: "X-Forwarded-Groups", value: !anonymous && app && groupPrefix ? `${groupPrefix}${app}-users` : "" },
    { name: "X-Forwarded-Subject", value: anonymous ? "" : SCAN_SUBJECT },
    { name: "X-Forwarded-Host", value: host },
    { name: "X-Forwarded-Proto", value: proto },
  ];
}

/**
 * A same-origin request's headers with the identity headers set: any copy
 * the page sent of one of them (any case) is dropped first, so the app sees
 * exactly what the front door would stamp, never what page script supplied.
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
 * http://storage.internal (the platform's storage relay in the app's host,
 * there once deployed), so a page that reads storage can fail here and work in
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

export async function waitHealthz(base, seconds) {
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
 * result with no scanned pages and an error string. `removeProfile` is
 * injected by the tests (the teardown's profile removal); unset, the
 * teardown's own runs.
 */
export async function scan({ base, routes, axeSource, app, groupPrefix, anonymous = false, chrome, budgetMs = SCAN_BUDGET_MS,
  removeProfile = /** @type {((dir: string) => void) | undefined} */ (undefined) }) {
  const deadline = Date.now() + budgetMs;
  const identity = identityHeaders({ base, app, groupPrefix, anonymous });
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
    await closeBrowser(proc, profile, { remove: removeProfile });
  }
}
