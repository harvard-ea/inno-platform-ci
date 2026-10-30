#!/usr/bin/env node
// Calls the platform broker's /deploy-complete endpoint after the deploy job
// has done its part (a function app's bundle hand-over, or a container app's
// image push), so the broker can finish the deploy (upload a function app's
// Worker from the bundle it staged, or a container app's host Worker with the
// pushed image), attach the app's hostname to the front door and mark the
// deployment (and app) live.
//
// Usage: node ci/deploy-finalize.mjs <brokerUrl> <app> <deploymentId> <token> [imageId] [image] [bundle]
// `token` is the GitHub Actions OIDC token (verified server-side).
// `imageId` (R11) is the image id the deploy job actually loaded and pushed;
// the broker refuses to promote the staged SBOM if it doesn't match what the
// container job recorded. `image` is the digest-pinned registry reference the
// push step wrote, which the broker checks is this app's own before it rolls
// it out. Both are empty for a function deploy. `bundle` is the digest the
// platform answered for the function bundle ci/deploy-bundle.mjs handed over
// (`sha256:<hex>`), which names the staged bundle the broker uploads; it is
// empty for a container deploy. An empty one of the three is sent as no
// field. It also reads app/inno-variables.json from the app checkout, if
// the app declared one, and sends it as `variables` so the broker can update
// the app's declared platform variables at the same time it marks the
// deployment live.
//
// A failure prints two lines on stderr (R7-5, v0.17.6): the message, plain,
// then one annotation titled "Deploy not finalized", whose fix is the
// broker's sentence when the refusal carries one (a script_rejected's carries
// Cloudflare's reason) and a re-run of the release's workflow otherwise
// (ci/broker-post.mjs reportRefusal). The release's workflow then runs
// ci/deploy-abandon.mjs, which releases the app from `deploying`.

import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { brokerPost, reportRefusal, withBusyRetry } from "./broker-post.mjs";
import { annotate, isMainModule, logSafe, parseIntegerArg } from "./cli.mjs";

// A FAILURE-SHAPE guard, not a security bound. The platform already refuses an
// oversized body at 64 KiB (readAppBody's DEFAULT_MAX_BODY_BYTES), but it does
// so with a 400 on the WHOLE finalize, which fails a deploy that already
// succeeded. Declining to send is the only way to keep "a bad metadata file
// never fails the deploy", and only this side can do it: by the time the
// platform can measure the field it has already read and bounded the body.
// 32 KiB is roughly 3x the largest file the platform's own caps can accept
// (32 names x [64-char name + 200-char description + syntax] is about 10 KB)
// and half the broker's body cap, so it can never refuse a valid file and can
// never be the thing that trips the broker's bound.
// test/doc-parity.node.test.ts pins the relationship to APP_VARIABLE_LIMIT and
// DESCRIPTION_MAX; this constant is NOT derived, because ci/ ships standalone
// in the public mirror and imports nothing from src/ on purpose.
export const MAX_DECLARATION_BYTES = 32 * 1024;

/**
 * Read `app/inno-variables.json` relative to `root`, the app checkout.
 *
 * A MISSING file is not an error: declaring is optional, and `undefined` here
 * means "send no field", which leaves the platform's existing declarations
 * alone rather than clearing them. Unparseable JSON, an unreadable file, and
 * one over MAX_DECLARATION_BYTES ARE reported, so the author sees it in the
 * run they are already watching. The platform is the authority on whether the
 * CONTENT is valid; this only decides whether there is something to send.
 */
export function readDeclarationFile(root = ".") {
  const path = join(root, "app", "inno-variables.json");
  if (!existsSync(path)) return { ok: true, variables: undefined };
  let text;
  try {
    // Inside the read try, not above it: statSync throws the same way
    // readFileSync does (the file can go away between existsSync and here),
    // and an uncaught throw in this script is exactly the failed deploy the
    // whole warn-and-send-nothing path exists to avoid.
    const size = statSync(path).size;
    if (size > MAX_DECLARATION_BYTES) {
      return {
        ok: false,
        error: `app/inno-variables.json is ${size} bytes; the limit is ${MAX_DECLARATION_BYTES}`,
      };
    }
    text = readFileSync(path, "utf8");
  } catch (err) {
    return { ok: false, error: `could not read app/inno-variables.json: ${err?.message ?? err}` };
  }
  try {
    return { ok: true, variables: JSON.parse(text) };
  } catch (err) {
    return { ok: false, error: `app/inno-variables.json is not valid JSON: ${err?.message ?? err}` };
  }
}

/**
 * POST {app, deployment_id, image_id?, image?, bundle?, variables?} to `${base}/deploy-complete`,
 * authenticated with the GitHub Actions OIDC token.
 *
 * The request fields are ONE options object, matching brokerPost (the
 * function this calls) and for the same reason. As seven positionals with
 * three optionals in the middle, a caller that kept passing `fetcher` in slot
 * 7 handed a function as `variables`; JSON.stringify drops function-valued
 * properties, so the body stayed correct while the injected fetcher was
 * silently replaced by the global one and the "test" started making real
 * network calls. Named fields make that a TypeError instead of a quiet
 * escape. Every ci/ broker helper takes its fields this way, with the
 * injectable `fetcher` after the object, outside it (brokerPost,
 * requestDeployToken, uploadSbom, handOver, requestAbandon, postFindings).
 *
 * @param {object} req
 * @param {string} req.base - broker base URL, e.g. "https://inno-platform.example.workers.dev"
 * @param {string} req.token - GitHub Actions OIDC token
 * @param {string} req.app
 * @param {number|string} req.deploymentId
 * @param {string} [req.imageId] - the image id actually deployed (R11); no field when empty
 * @param {string} [req.image] - the digest-pinned image reference the push step wrote; no field when empty
 * @param {string} [req.bundle] - the staged function bundle's digest (`sha256:<hex>`); no field when empty
 * @param {Record<string, unknown>} [req.variables] - the app's declared platform variables
 *   (from app/inno-variables.json), or undefined to send no field
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} [fetcher]
 *   - injectable for testing; defaults to global fetch
 * @param {(ms: number) => Promise<void>} [wait] - the pause between busy retries; injectable for testing
 * @returns {Promise<any>} the parsed JSON response body (e.g. { url })
 */
export async function finalize({ base, token, app, deploymentId, imageId, image, bundle, variables }, fetcher = fetch, wait) {
  const body = {
    app, deployment_id: deploymentId,
    ...(imageId ? { image_id: imageId } : {}),
    ...(image ? { image } : {}),
    ...(bundle ? { bundle } : {}),
    ...(variables !== undefined ? { variables } : {}),
  };
  // A 409 app_busy (another change holds the app's lease) is retried on
  // ci/broker-post.mjs's one schedule: failing there would fail a deploy CI
  // has already handed over, leaving the app `deploying` until the job is
  // re-run.
  return withBusyRetry("deploy-complete", () => brokerPost(
    { base, path: "/deploy-complete", label: "deploy-complete", token, body, timeoutMs: FINALIZE_TIMEOUT_MS },
    fetcher,
  ), wait);
}

// How long the finalize waits for /deploy-complete's answer: a bound of its
// own, not brokerPost's default (BROKER_TIMEOUT_MS, sized for the short
// reports). A container app's finalize answers only once the platform has
// rolled the image out (up to 180 s, src/hosts.ts ROLLOUT_TIMEOUT_MS),
// uploaded the host (Cloudflare's upload timeout, 60 s), checked the app's
// host in DNS (two reads) and attached it (each of those three calls 30 s at
// most), and committed the deployment; a shorter bound fails a slow but
// healthy deploy that the platform goes on to finish. It also stays a
// minute inside the app lease the finalize runs under (src/app-lease.ts
// LEASE_TTL_MS, 10 minutes): when CI gives up, the job's last step asks
// /deploy-abandon to release the app under that same lease, and must meet it
// still held (app_busy, the app left to the recovery sweep) rather than take
// it over from a rollout that already landed. No answer within it throws
// `deploy-complete failed: no answer within 540 s`, which is not retried.
// test/doc-parity.node.test.ts pins it above that sum and below the lease;
// it is NOT derived, because ci/ ships standalone in the public mirror and
// imports nothing from src/ on purpose.
export const FINALIZE_TIMEOUT_MS = 540_000;

if (isMainModule(import.meta.url)) {
  try {
    const [base, app, deploymentId, token, imageIdArg, imageArg, bundleArg] = process.argv.slice(2);
    if (!base || !app || !deploymentId || !token) {
      throw new Error("Usage: node ci/deploy-finalize.mjs <brokerUrl> <app> <deploymentId> <token> [imageId] [image] [bundle]");
    }
    // The broker's /deploy-token response is where this came from (via
    // `jq -r .deployment_id`); parseIntegerArg says what a malformed one
    // looks like rather than POSTing it back to the broker.
    const deploymentIdNum = parseIntegerArg("deploymentId", deploymentId);
    const declared = readDeclarationFile(".");
    if (!declared.ok) {
      // A workflow annotation, not a failure: the platform keeps its previous
      // declarations and the deploy is unaffected. MUST stay on stderr, as
      // annotate writes it: the workflow captures this script's stdout into
      // `$result` and pipes it straight into `jq -r .url` (platform-ci.yml's
      // "Finalize deployment" step) under `set -e`. A non-JSON line on
      // stdout makes that jq call fail, which turns this exact "warn, don't
      // fail" case into a failed deploy, the opposite of the intent.
      // annotate flattens the error: JSON.parse's message embeds a snippet of
      // the raw file, so an author-chosen newline would otherwise forge a
      // second, well-formed workflow-command line in this step's log.
      annotate({ level: "warning", title: "Declared variables", file: "app/inno-variables.json", what: declared.error });
    }
    const result = await finalize({
      base, token, app,
      deploymentId: deploymentIdNum,
      imageId: imageIdArg,
      image: imageArg,
      bundle: bundleArg,
      variables: declared.ok ? declared.variables : undefined,
    });
    // Human-readable line to stderr; the raw JSON result to stdout, so the
    // workflow can capture stdout and pipe it straight into `jq -r .url`
    // instead of re-parsing this log line with sed. The log line is
    // flattened: the answer echoes an author's declared key back in
    // variables_refused, which must not carry the runner's ##[ marker into
    // the log. stdout stays raw, as jq reads it into a variable and nothing
    // prints it.
    console.error(`deploy-complete: ${logSafe(JSON.stringify(result), Infinity)}`);
    console.log(JSON.stringify(result));
  } catch (err) {
    const raw = String(err?.message ?? err);
    if (raw.startsWith("Usage:")) {
      console.error(raw);
    } else {
      // A malformed deployment id is this CLI's own refusal, and reads as it is.
      reportRefusal(err, {
        label: "deploy-complete", title: "Deploy not finalized", fix: "re-run the release's workflow", asIs: ["invalid deploymentId"],
      });
    }
    process.exitCode = 1;
  }
}
