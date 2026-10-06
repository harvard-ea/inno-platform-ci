#!/usr/bin/env node
// Calls the platform broker's /deploy-complete endpoint after `wrangler
// deploy` succeeds, so the broker can attach the app's DNS/domain and mark
// the deployment (and app) as live.
//
// Usage: node ci/deploy-finalize.mjs <brokerUrl> <app> <deploymentId> <token> [gatewayRef] [imageId]
// `token` is the GitHub Actions OIDC token (verified server-side).
// `gatewayRef` records which promoted gateway build was injected into this
// deploy. `imageId` (R11) is the image id the deploy job actually loaded and
// pushed; the broker refuses to promote the staged SBOM if it doesn't match
// what the container job recorded. It also reads app/inno-variables.json
// from the app checkout, if the app declared one, and sends it as
// `variables` so the broker can update the app's declared platform variables
// at the same time it marks the deployment live.

import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { brokerPost } from "./broker-post.mjs";
import { isMainModule, logSafe, parseIntegerArg } from "./cli.mjs";

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
 * POST {app, deployment_id, gateway_ref?, image_id?, variables?} to `${base}/deploy-complete`,
 * authenticated with the GitHub Actions OIDC token.
 *
 * The request fields are ONE options object, matching brokerPost (the
 * function this calls) and for the same reason. As seven positionals with
 * three optionals in the middle, a caller that kept passing `fetcher` in slot
 * 7 handed a function as `variables`; JSON.stringify drops function-valued
 * properties, so the body stayed correct while the injected fetcher was
 * silently replaced by the global one and the "test" started making real
 * network calls. Named fields make that a TypeError instead of a quiet
 * escape. `fetcher` stays the last parameter, outside the object, like every
 * sibling helper's (uploadSbom, postResults, postDepsResults, brokerPost).
 *
 * @param {object} req
 * @param {string} req.base - broker base URL, e.g. "https://inno-platform.example.workers.dev"
 * @param {string} req.token - GitHub Actions OIDC token
 * @param {string} req.app
 * @param {number|string} req.deploymentId
 * @param {string} [req.gatewayRef] - optional gateway reference
 * @param {string} [req.imageId] - the image id actually deployed (R11)
 * @param {Record<string, unknown>} [req.variables] - the app's declared platform variables
 *   (from app/inno-variables.json), or undefined to send no field
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} [fetcher]
 *   - injectable for testing; defaults to global fetch
 * @returns {Promise<any>} the parsed JSON response body (e.g. { url })
 */
export async function finalize({ base, token, app, deploymentId, gatewayRef, imageId, variables }, fetcher = fetch) {
  const body = {
    app, deployment_id: deploymentId,
    ...(gatewayRef ? { gateway_ref: gatewayRef } : {}),
    ...(imageId ? { image_id: imageId } : {}),
    ...(variables !== undefined ? { variables } : {}),
  };
  return brokerPost(
    { base, path: "/deploy-complete", label: "deploy-complete", token, body },
    fetcher,
  );
}

if (isMainModule(import.meta.url)) {
  try {
    const [base, app, deploymentId, token, gatewayRefArg, imageIdArg] = process.argv.slice(2);
    if (!base || !app || !deploymentId || !token) {
      throw new Error("Usage: node ci/deploy-finalize.mjs <brokerUrl> <app> <deploymentId> <token> [gatewayRef] [imageId]");
    }
    // The broker's /deploy-token response is where this came from (via
    // `jq -r .deployment_id`); parseIntegerArg says what a malformed one
    // looks like rather than POSTing it back to the broker.
    const deploymentIdNum = parseIntegerArg("deploymentId", deploymentId);
    const declared = readDeclarationFile(".");
    if (!declared.ok) {
      // A workflow annotation, not a failure: the platform keeps its previous
      // declarations and the deploy is unaffected. MUST stay console.error
      // (stderr), not console.log: the workflow captures this script's
      // stdout into `$result` and pipes it straight into `jq -r .url`
      // (platform-ci.yml's "Finalize deployment" step) under `set -e`. A
      // non-JSON line on stdout makes that jq call fail, which turns this
      // exact "warn, don't fail" case into a failed deploy - the opposite of
      // the intent. Other ci/ scripts (e.g. check-dep-age.mjs) use
      // console.log for their own `::warning::` lines, but none of them has
      // a caller that parses their stdout as JSON; that precedent does not
      // apply here.
      // logSafe, not the raw error: JSON.parse's message embeds a snippet of
      // the raw file, so an author-chosen newline would otherwise forge a
      // second, well-formed workflow-command line in this step's log.
      console.error(`::warning title=Declared variables::${logSafe(declared.error)}`);
    }
    const result = await finalize({
      base, token, app,
      deploymentId: deploymentIdNum,
      gatewayRef: gatewayRefArg,
      imageId: imageIdArg,
      variables: declared.ok ? declared.variables : undefined,
    });
    // Human-readable line to stderr; the raw JSON result to stdout, so the
    // workflow can capture stdout and pipe it straight into `jq -r .url`
    // instead of re-parsing this log line with sed.
    console.error(`deploy-complete: ${JSON.stringify(result)}`);
    console.log(JSON.stringify(result));
  } catch (err) {
    console.error(String(err?.message ?? err));
    process.exitCode = 1;
  }
}
