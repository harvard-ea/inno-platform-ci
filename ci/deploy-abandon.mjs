#!/usr/bin/env node
// Releases an app from a deploy that failed, for the deploy job's last step,
// "Release the app after a failed deploy" (R7-3, v0.17.6). It runs only when
// the job has failed after /deploy-token started a deployment (`if:
// failure()` and a deployment id), and asks the platform's /deploy-abandon to
// mark that deployment abandoned and return the app from `deploying` to what
// it was, at once, instead of leaving it for the lifecycle pass's recovery
// sweep, which waits two run intervals (at least 2 hours). The platform
// releases only this run's own deployment, and only while it is the app's
// latest and still deploying.
//
// Usage: node ci/deploy-abandon.mjs <brokerUrl> <app> <deploymentId> <token>
// `token` is a fresh GitHub Actions OIDC token (audience
// inno-platform-deploy), minted by the step before this one.
//
// The job has already failed when this runs, so this step adds no failure:
// once its arguments parse it exits 0 whatever the platform answers, and
// says what happened in one annotation on stderr (ci/cli.mjs annotate; stdout
// stays empty). Released: a notice naming the state the app is back in.
// Refused as not this app's deploy in flight (`deployment_not_abandonable`,
// e.g. a finalize that completed first): a notice with the platform's
// sentence, since there is nothing to release. Anything else, no answer
// within the bound, or a platform from before this route (a bare 405 from
// its asset router): a warning that the recovery sweep releases the app
// later. A 409 app_busy (a finalize still running under the app's lease, or
// another change to the app) is retried on ci/broker-post.mjs's one
// schedule; each attempt waits at most
// ABANDON_TIMEOUT_MS. A missing or empty token means the step before this
// one, which mints it, failed: that is the job's failure already, so it is
// the same warning and exit 0, with no request sent, rather than a second
// red step (v0.17.6, build decision 16). Exit 1, with the usage, only on the
// other arguments not parsing.

import { brokerPost, refusalParts, withBusyRetry } from "./broker-post.mjs";
import { annotate, isMainModule, logSafe, parseIntegerArg } from "./cli.mjs";

// How long each attempt waits for its answer: the platform's release is a
// few writes under the app's lease, as quick as the token request it undoes
// (ci/deploy-token.mjs DEPLOY_TOKEN_TIMEOUT_MS).
export const ABANDON_TIMEOUT_MS = 30_000;

const USAGE = "Usage: node ci/deploy-abandon.mjs <brokerUrl> <app> <deploymentId> <token>";

// The warning's fix, for every way the platform did not release the app.
const SWEEP_RELEASES = "its recovery sweep releases it once two run intervals (at least 2 hours) have passed since the deploy began";

/**
 * POST {app, deployment_id} to `${base}/deploy-abandon` with the OIDC bearer,
 * retrying a 409 app_busy alone, and answer the release. Throws the
 * broker-post error on a refusal (`deploy-abandon failed (<status>): ...`,
 * its status and body beside the message) or no answer, and on a 2xx that
 * names no release.
 *
 * @param {object} req
 * @param {string} req.base - broker base URL
 * @param {string} req.app
 * @param {number} req.deploymentId - the deployment /deploy-token started
 * @param {string} req.token - GitHub Actions OIDC token
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} [fetcher]
 *   - injectable for testing; defaults to global fetch
 * @param {(ms: number) => Promise<void>} [wait] - the pause between busy retries; injectable for testing
 * @returns {Promise<{ released: true, revert_to: "active" | "created" }>}
 */
export async function requestAbandon({ base, app, deploymentId, token }, fetcher = fetch, wait) {
  const answer = await withBusyRetry("deploy-abandon", () => brokerPost(
    { base, path: "/deploy-abandon", label: "deploy-abandon", token, body: { app, deployment_id: deploymentId }, timeoutMs: ABANDON_TIMEOUT_MS },
    fetcher,
  ), wait);
  if (answer?.released !== true || (answer.revert_to !== "active" && answer.revert_to !== "created")) {
    throw new Error("deploy-abandon failed: the broker's answer names no release");
  }
  return { released: true, revert_to: answer.revert_to };
}

/**
 * Why the platform did not release the app, for the warning: the HTTP
 * status and the refusal's code, a 405 with no code read as a platform from
 * before this route (its asset router's answer), and otherwise what the
 * failure said after its label (`no answer within 30 s`), with the
 * network's own code when there was no connection at all (`fetch failed
 * (ECONNREFUSED)`).
 *
 * @param {any} err - what requestAbandon threw
 * @returns {string}
 */
function notReleasedDetail(err) {
  if (typeof err?.status === "number") {
    const { error } = refusalParts(err.body);
    if (err.status === 405 && error === null) return "HTTP 405 (this platform has no /deploy-abandon)";
    return `HTTP ${err.status}${error === null ? "" : ` ${error}`}`;
  }
  const said = String(err?.message ?? err).replace(/^deploy-abandon failed: /, "");
  const code = typeof err?.cause?.code === "string" ? ` (${err.cause.code})` : "";
  return logSafe(`${said}${code}`, 200);
}

if (isMainModule(import.meta.url)) {
  let req;
  try {
    const [base, app, deploymentId, token = "", ...rest] = process.argv.slice(2);
    if (!base || !app || !deploymentId || rest.length) throw new Error(USAGE);
    req = { base, app, deploymentId: parseIntegerArg("deploymentId", deploymentId), token };
  } catch (err) {
    console.error(logSafe(String(err?.message ?? err), 1000));
    process.exitCode = 1;
  }
  if (req && !req.token) {
    annotate({
      level: "warning", title: "App not released",
      what: `the platform did not release ${req.app} (no OIDC token to ask with: the step that mints it failed)`,
      fix: SWEEP_RELEASES,
    });
  } else if (req) {
    const { app, deploymentId } = req;
    try {
      const { revert_to } = await requestAbandon(req);
      annotate({
        level: "notice", title: "App released",
        what: `the platform released ${app} from its failed deploy (deployment ${deploymentId})`,
        fix: `it is ${revert_to} again; fix what failed above, then release again`,
      });
    } catch (err) {
      const { error, message } = refusalParts(err?.body);
      if (err?.status === 409 && error === "deployment_not_abandonable") {
        annotate({ level: "notice", title: "Nothing to release", what: message ?? error, fix: "" });
      } else {
        annotate({
          level: "warning", title: "App not released",
          what: `the platform did not release ${app} (${notReleasedDetail(err)})`,
          fix: SWEEP_RELEASES,
        });
      }
    }
  }
}
