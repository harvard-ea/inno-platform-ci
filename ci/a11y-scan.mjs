#!/usr/bin/env node
// Accessibility + response-header REPORT for a container app's built image
// (contract §3 and R8; guidance in docs/APP-ACCESSIBILITY.md).
//
// The container job's smoke test already runs the exact image that will
// deploy, on the runner, with no front door in front of it. This script
// points a headless Chromium at that container, sends the headers the front
// door would stamp (R3; see identityHeaders) to the app's own origin only,
// runs axe-core on each route, and reports:
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
//     [--identity identity-aware|anonymous]
//     [--mode report|enforce] [--ignore "<rule ids, space-separated>"]
//     [--routes <inno-a11y.json>] [--summary <file>] [--json <file>]
//     [--chrome <binary>] [--wait-healthz <seconds>] [--instance <instance.json>]
//
// --identity is the app's identity as /ci/policy serves it. An anonymous app
// is told nobody's identity by the front door, so it is scanned with the four
// identity headers empty, as it is served; any other value, or none, scans
// it as a synthetic member (identityHeaders).
//
// The synthetic user's group is built from the instance's group prefix, read
// from --instance <path>, else INNO_INSTANCE_JSON (the JSON itself, not a
// path), else the ci/instance.json beside this script (ci/cli.mjs
// loadInstanceData). Tenant CI runs the scanner under `docker run`, which
// passes it no environment, and mounts ci/ into its container whole, so the
// default is the one it uses.
//
// This file is the CLI. Since v0.18.16 (CI-08) the rest lives in ci/a11y/:
// cdp.mjs the browser and its DevTools client, scan.mjs the scan, and
// report.mjs the verdict, the step summary and the annotations. The mirror
// publishes all four, and tenant CI mounts ci/ whole into the scanner's
// container. The entry still exports every name it exported before the
// split, each the binding of the module that owns it.
//
// Zero npm dependencies (node builtins, cli.mjs and ci/a11y/), like every ci/
// script: it drives Chromium over the DevTools protocol on
// --remote-debugging-pipe, so the only third-party code is the browser in the
// digest-pinned Playwright image and the axe-core file the workflow fetches
// and verifies against its published sha512 integrity before calling this.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { annotationLine, isMainModule, loadInstanceData, logSafe } from "./cli.mjs";
import { annotations, evaluate, headerFindings, parseIgnores, parseMode, renderSummary } from "./a11y/report.mjs";
import { parseIdentity, parseRoutes, scan, waitHealthz } from "./a11y/scan.mjs";

export { BROWSER_EXIT_WAIT_MS, PROFILE_REMOVE_DELAY_MS, PROFILE_REMOVE_TRIES, closeBrowser, findChrome } from "./a11y/cdp.mjs";
export {
  ANNOTATIONS_PER_KIND, BLOCKING_IMPACTS, annotations, cell, code, evaluate, headerFindings, parseIgnores, parseMode, renderSummary,
} from "./a11y/report.mjs";
export {
  APP_FAULT_STATUSES, AXE_TAGS, IMPACT_ORDER, MAX_ROUTES, SCAN_BUDGET_MS, SCAN_SUBJECT, SCAN_USER, identityHeaders, parseIdentity,
  parseRoutes, responseStatus, sanitizeViolations, scan, scanRoute, withIdentity,
} from "./a11y/scan.mjs";

const USAGE = "Usage: node ci/a11y-scan.mjs --base <url> --axe <axe.min.js> [--app <name>] " +
  "[--identity identity-aware|anonymous] " +
  "[--mode report|enforce] [--ignore \"<rule ids, space-separated>\"] [--routes <inno-a11y.json>] " +
  "[--summary <file>] [--json <file>] [--chrome <binary>] [--wait-healthz <seconds>] [--instance <instance.json>]";
// Every flag in USAGE. Anything else is refused rather than skipped: a typo
// such as --wait-heathz would otherwise drop the setting it meant without a
// word, and an unquoted --ignore list would lose all but its first rule id.
const FLAGS = new Set(["base", "axe", "app", "identity", "mode", "ignore", "routes", "summary", "json", "chrome", "wait-healthz", "instance"]);

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

/**
 * The options main() hands scan() from its arguments and the instance's
 * group prefix: the one place --identity becomes `anonymous` (only
 * "anonymous" reads as anonymous, parseIdentity), so a test can see what an
 * anonymous app is scanned as without a browser (OPEN 90).
 *
 * @param {Record<string, string>} args - parseArgs' answer
 * @param {string | null} groupPrefix - the instance's group prefix
 * @returns {{ base: string, app: string, groupPrefix: string | null, anonymous: boolean, chrome: string }}
 */
export function scanOptions(args, groupPrefix) {
  return {
    base: args.base,
    app: args.app,
    groupPrefix,
    anonymous: parseIdentity(args.identity) === "anonymous",
    chrome: args.chrome,
  };
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
  if (!result) result = await scan({ ...scanOptions(args, groupPrefix), routes, axeSource });
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
  // blocks, which covers crashes before this module even loads.) A crash
  // ends the process at once, with 3: the one process.exit the exit-code
  // rule allows (ci/cli.mjs), since a handler that returned would leave a
  // process in an unknown state running, the browser it started attached.
  // Every verdict sets the exit code and lets the process end on its own,
  // so the lines main() printed reach a piped stdout whole.
  const crashed = (e) => {
    console.log(annotationLine({ level: "warning", title: "Accessibility scan crashed",
      what: `${logSafe(e && e.message ? e.message : e, 200)} (platform-side; not blocking)` }));
    process.exit(3);
  };
  process.on("uncaughtException", crashed);
  process.on("unhandledRejection", crashed);
  main().then((code) => { process.exitCode = code; }).catch(crashed);
}
