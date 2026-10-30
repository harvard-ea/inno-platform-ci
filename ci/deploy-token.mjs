#!/usr/bin/env node
// Asks the platform broker's /deploy-token to start a deploy, for the deploy
// job's "Request deploy token from broker" step, and prints the three fields
// of its answer the later steps read, as one JSON object on stdout:
// `{"token":"...","deployment_id":7,"image_id":"..."}`. `token` is a
// container app's push-only Cloudflare token and `image_id` the scanned
// image's id the container job recorded; a function app's answer carries
// neither (the platform uploads its Worker), and each is then "". The step
// masks the token before anything else is logged and writes the three to its
// outputs. The answer's other fields (expires_on, shape, perimeter) are read
// by no step and are not printed.
//
// Usage: node ci/deploy-token.mjs <brokerUrl> <app> <token>
// `token` is the GitHub Actions OIDC token (audience inno-platform-deploy).
//
// The request names the app and nothing else, and it is NOT idempotent: each
// call inserts a deployment row, flips the app to `deploying` and, for a
// container app, mints a 15-minute push-only token. So nothing retries it but
// the broker's lease refusal, 409 app_busy, which the broker answers before
// it writes anything (revoking any token it minted for the refused call), on
// ci/broker-post.mjs's one schedule (withBusyRetry). Every other answer, a
// 409 for a stopped app or a link refusal included, fails the step at once
// with the broker's own sentence, which names the fix. Until v0.17.3 this was
// a bash loop around curl in the step itself, with its own copy of the
// schedule (R7-3).
//
// A failure prints two lines on stderr (R7-5, v0.17.6): the message, plain,
// as the step log has always shown it, then one annotation titled "Deploy
// refused", whose fix is the broker's sentence when the refusal carries one
// and a re-run of the release's workflow otherwise (ci/broker-post.mjs
// reportRefusal, the one way the CLIs that end on a broker refusal report
// it).

import { brokerPost, reportRefusal, withBusyRetry } from "./broker-post.mjs";
import { isMainModule } from "./cli.mjs";

// How long the request waits for its answer: 30 s, shorter than brokerPost's
// default for the reports (BROKER_TIMEOUT_MS). The broker does a deployment's
// first writes (and, for a container app, mints the push token) before it
// answers, which takes seconds; a broker that holds the connection longer is
// failing, and the job is re-run. No answer within it throws
// `deploy-token failed: no answer within 30 s`, which is not retried.
export const DEPLOY_TOKEN_TIMEOUT_MS = 30_000;

/**
 * POST {app} to `${base}/deploy-token` with the OIDC bearer, retrying a 409
 * app_busy alone, and answer the three fields the deploy job reads. Throws on
 * a refusal (brokerPost's `deploy-token failed (<status>): ...`) and on an
 * answer that names no deployment, which no later step could finalize.
 *
 * @param {object} req
 * @param {string} req.base - broker base URL
 * @param {string} req.app
 * @param {string} req.token - GitHub Actions OIDC token
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} [fetcher]
 *   - injectable for testing; defaults to global fetch
 * @param {(ms: number) => Promise<void>} [wait] - the pause between busy retries; injectable for testing
 * @returns {Promise<{ token: string, deployment_id: number, image_id: string }>}
 */
export async function requestDeployToken({ base, app, token }, fetcher = fetch, wait) {
  const answer = await withBusyRetry("deploy-token", () => brokerPost(
    { base, path: "/deploy-token", label: "deploy-token", token, body: { app }, timeoutMs: DEPLOY_TOKEN_TIMEOUT_MS },
    fetcher,
  ), wait);
  if (!Number.isSafeInteger(answer?.deployment_id)) {
    throw new Error("deploy-token failed: the broker's answer names no deployment_id");
  }
  return {
    token: typeof answer.token === "string" ? answer.token : "",
    deployment_id: answer.deployment_id,
    image_id: typeof answer.image_id === "string" ? answer.image_id : "",
  };
}

const USAGE = "Usage: node ci/deploy-token.mjs <brokerUrl> <app> <token>";

if (isMainModule(import.meta.url)) {
  const [base, app, token] = process.argv.slice(2);
  if (!base || !app || !token) {
    console.error(USAGE);
    process.exitCode = 1;
  } else {
    try {
      // stdout is the JSON alone: the step parses it with jq. Everything else,
      // the retries' lines and a refusal, goes to stderr.
      console.log(JSON.stringify(await requestDeployToken({ base, app, token })));
    } catch (err) {
      reportRefusal(err, { label: "deploy-token", title: "Deploy refused", fix: "re-run the release's workflow" });
      process.exitCode = 1;
    }
  }
}
