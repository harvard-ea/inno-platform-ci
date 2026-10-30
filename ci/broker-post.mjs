// jsonRequest: the text-first JSON request that brokerPost,
// scripts/cf-api.mjs's apiReq and ci/export-app.mjs's R2 list make through.
// It sends a JSON body when there is one, reads the response as text FIRST
// (so a non-2xx, non-JSON body, such as an HTML 500 page, surfaces the real
// status and body instead of a raw JSON parse error), throws
// `<label> failed (<status>): <error>: <message>` on a non-2xx answer that is
// a JSON refusal with a string `error` and `message` (the broker's shape, the
// message flattened and bounded at REFUSAL_MESSAGE_MAX_CHARS) and
// `<label> failed (<status>): <200-character snippet>` on any other, and
// parses the body on success. Which of the files that import this one
// ship in the public mirror is scripts/publish-mirror.sh's manifest
// (test-enforced), not a list kept here. The callers:
//   - brokerPost, below: the POST to a broker endpoint with the GitHub Actions
//     OIDC token as a bearer, which the ci/ scripts that report to the broker
//     share. Every broker endpoint answers a JSON object, so brokerPost
//     refuses an empty body, and a body that is the literal JSON `null`, each
//     with its own message, rather than let a report pass that the broker may
//     never have read.
//   - scripts/cf-api.mjs's apiReq, the Cloudflare API call of the operator
//     scripts built on it, scripts/check-okta-server.mjs and
//     scripts/placeholders.mjs.
//   - ci/export-app.mjs's R2 list. Its object GET stays raw: it streams the
//     body to disk.
//
// withBusyRetry, last below, is the one retry of the broker's lease refusal
// (409 app_busy) on the one schedule, BUSY_RETRY_DELAYS_MS: tenant CI's
// token request (ci/deploy-token.mjs), finalize (ci/deploy-finalize.mjs) and
// release of a failed deploy's app (ci/deploy-abandon.mjs) all run through
// it. refusalParts reads a refusal's code and sentence apart, and
// reportRefusal is the one way the four CLIs that end on a broker refusal
// (ci/deploy-token.mjs, ci/deploy-finalize.mjs, ci/sbom-upload.mjs,
// ci/deploy-bundle.mjs) report it (R7-deploy-ci-7).
//
// Every request is bounded: no answer, or no end to it, within the caller's
// timeoutMs (BROKER_TIMEOUT_MS when absent) throws
// `<label> failed: no answer within <n> s`, so a broker that accepts the
// connection and never answers cannot hold a job until its own timeout. The
// default is the short reports' (an SBOM, a sweep's or the dependency gate's
// results, an export's end, an R2 list, an operator script's Cloudflare
// call), whose answers are quick. The token request, the finalize and the
// release each wait on a bound of their own (ci/deploy-token.mjs
// DEPLOY_TOKEN_TIMEOUT_MS, ci/deploy-finalize.mjs FINALIZE_TIMEOUT_MS,
// ci/deploy-abandon.mjs ABANDON_TIMEOUT_MS): the first and the last are
// shorter, the finalize longer, since a container app's finalize answers only
// after the platform has rolled the image out and uploaded the host.
//
// One import on purpose, ./cli.mjs, for logSafe, the ci/ log sanitiser, and
// annotate, the one annotation rule: it ships beside this file in the mirror
// manifest and imports only Node's own modules, so the mirror ships no extra
// file for these helpers and nothing that imports them takes on a dependency
// beyond Node. Both request helpers use the global fetch, injectable for
// tests.
import { annotate, logSafe } from "./cli.mjs";

// The most of a refusal's message the thrown error carries: room for the
// longest the platform writes, a finalize's script_rejected quoting up to
// 2000 characters of Cloudflare's answer (src/clients/cf-scripts.ts
// SCRIPT_UPLOAD_MAX_ERROR_BODY) after its own words.
export const REFUSAL_MESSAGE_MAX_CHARS = 4000;

// How long a request waits for its answer when its caller names no bound.
export const BROKER_TIMEOUT_MS = 180_000;

/**
 * The two parts of a broker refusal, read from an answer's body: `error`, the
 * code, and `message`, the platform's sentence, which names the fix. Each is
 * its string flattened by logSafe (parsing turns the JSON's escapes back into
 * the characters they stand for, a newline among them, which would start a
 * forged workflow command in the run's log), the code bounded at 200
 * characters and the sentence at REFUSAL_MESSAGE_MAX_CHARS; a part the body
 * does not carry as a string, and both for a body that is not a JSON object,
 * is null. reportRefusal, below, reads it from the error's `body` for the
 * four CLIs that end on a refusal, and ci/deploy-abandon.mjs, whose
 * annotations are its own, reads it the same way.
 *
 * @param {string} text
 * @returns {{ error: string | null, message: string | null }}
 */
export function refusalParts(text) {
  let j;
  try { j = JSON.parse(text); } catch { return { error: null, message: null }; }
  if (!j || typeof j !== "object" || Array.isArray(j)) return { error: null, message: null };
  return {
    error: typeof j.error === "string" ? logSafe(j.error) : null,
    message: typeof j.message === "string" ? logSafe(j.message, REFUSAL_MESSAGE_MAX_CHARS) : null,
  };
}

// What the thrown error says of a non-2xx answer. A JSON refusal with a string
// `error` and `message`, the shape every broker refusal takes, reads as
// `<error>: <message>` (refusalParts, flattened and bounded), so the log
// shows the platform's sentence (and, for a script_rejected, Cloudflare's
// reason for refusing the Worker upload) rather than its first 200 characters
// cut inside the JSON framing. Any other answer, an HTML error page or a
// refusal without both fields (`{"error":"app_busy"}`), is its first 200
// characters, as it always was. Exported for ci/deploy-bundle.mjs, whose
// hand-over sends its bytes itself and reads a refusal through this, so it
// says what jsonRequest says of the same answer.
export function refusalText(text) {
  const { error, message } = refusalParts(text);
  return error !== null && message !== null ? `${error}: ${message}` : text.slice(0, 200);
}

/**
 * Report the failure a CLI ends on, on stderr, one way for the four that end
 * on a broker refusal (R7-deploy-ci-7): a plain line, the message whole and
 * flattened (the step log keeps what the annotation's bound cuts), then one
 * annotation. When the refusal carries the broker's sentence (refusalParts of
 * the error's `body`), the annotation's what is `<label> failed (<status>):
 * <code>` and its fix the sentence, which names the fix; otherwise its what
 * is the plain line and its fix the CLI's own. A message that does not
 * already start `<label> failed`, or with a prefix in `asIs` (the CLI's own
 * words for a malformed argument), is a failure below the request, with no
 * label of its own (no connection at all, an unreadable file), so the line
 * says whose it is: `<label> failed: <message>`. The plain line keeps
 * `<label> failed (<status>): <error>: <message>`, the form the app plugin's
 * failure tables quote.
 *
 * @param {unknown} err - what the CLI's work threw
 * @param {{ label: string, title: string, fix: string, asIs?: string[] }} o
 *   - label: the request's label, e.g. "deploy-token"; title: the
 *   annotation's; fix: the CLI's own remedy, for a failure with no sentence
 *   of the broker's ("" for none); asIs: message prefixes printed as they are
 */
export function reportRefusal(err, { label, title, fix, asIs = [] }) {
  const message = String(err?.message ?? err);
  const said = [`${label} failed`, ...asIs].some((p) => message.startsWith(p)) ? message : `${label} failed: ${message}`;
  console.error(logSafe(said, Infinity));
  const { error, message: sentence } = refusalParts(err?.body);
  const carried = error !== null && sentence !== null;
  annotate({
    title,
    what: carried ? `${label} failed (${err.status}): ${error}` : said,
    fix: carried ? sentence : fix,
  });
}

/**
 * Send a JSON request and return the parsed JSON response.
 *
 * Reads the body as text first so a non-2xx, non-JSON body (e.g. an HTML 500
 * page) surfaces the real status and body instead of a raw JSON parse error.
 *
 * @param {object} req
 * @param {string} req.url - the full request URL
 * @param {string} req.method - e.g. "GET", "POST"
 * @param {Record<string, string>} req.headers - the caller's headers (auth); Content-Type is added when there is a body
 * @param {any} [req.body] - JSON.stringify'd as-is when present
 * @param {string} req.label - error-message prefix, e.g. "deploy-complete" -> "deploy-complete failed (...)"
 * @param {number} [req.timeoutMs] - how long to wait for the answer; BROKER_TIMEOUT_MS when absent
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} [fetcher]
 *   - injectable for testing; defaults to global fetch
 * @returns {Promise<any>} the parsed JSON response body, or null on an empty body
 * @throws {Error & { status: number, body: string }} on a non-2xx answer
 * @throws {Error} when no answer, or no end to it, arrives within timeoutMs
 */
export async function jsonRequest({ url, method, headers, body, label, timeoutMs = BROKER_TIMEOUT_MS }, fetcher = fetch) {
  const hasBody = body !== undefined;
  let res;
  let text;
  try {
    res = await fetcher(url, {
      method,
      headers: { ...headers, ...(hasBody ? { "Content-Type": "application/json" } : {}) },
      ...(hasBody ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(timeoutMs),
    });
    text = await res.text();
  } catch (e) {
    if (e?.name === "TimeoutError") throw new Error(`${label} failed: no answer within ${timeoutMs / 1000} s`);
    throw e;
  }
  if (!res.ok) {
    // The status and the whole body ride on the error beside the message, so a
    // caller can decide on the answer (deploy-finalize.mjs retries a 409
    // app_busy and nothing else) without parsing the message.
    throw Object.assign(new Error(`${label} failed (${res.status}): ${refusalText(text)}`), {
      status: res.status, body: text,
    });
  }
  return text ? JSON.parse(text) : null;
}

/**
 * POST a JSON body to `${base}${path}` on the platform broker, authenticated
 * with the GitHub Actions OIDC token, and return the parsed JSON response
 * (see jsonRequest for the read and the error shape). An empty 2xx body throws
 * `<label> failed: empty response body`: the broker always answers JSON, so
 * an empty one came from something else, and the caller's report may never
 * have reached it. jsonRequest answers null for a body that is the literal
 * JSON `null` too, which no broker route answers either; that one throws
 * `<label> failed: JSON null response body`, so the two read apart. The text
 * is read through a wrapper around the fetcher, since jsonRequest's answer
 * alone cannot tell them apart and its other callers rely on its null.
 *
 * @param {object} req
 * @param {string} req.base - broker base URL, e.g. "https://inno-platform.example.workers.dev"
 * @param {string} req.path - endpoint path beginning with "/", e.g. "/deploy-complete"
 * @param {string} req.label - error-message prefix, e.g. "deploy-complete" -> "deploy-complete failed (...)"
 * @param {string} req.token - GitHub Actions OIDC token
 * @param {any} req.body - request body, JSON.stringify'd as-is
 * @param {number} [req.timeoutMs] - how long to wait for the answer; BROKER_TIMEOUT_MS when absent
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} [fetcher]
 *   - injectable for testing; defaults to global fetch
 * @returns {Promise<any>} the parsed JSON response body
 * @throws {Error & { status: number, body: string }} on a non-2xx answer
 * @throws {Error} on an empty 2xx body, or one that is the JSON null, or no answer within timeoutMs
 */
export async function brokerPost({ base, path, label, token, body, timeoutMs }, fetcher = fetch) {
  let text = "";
  const answer = await jsonRequest(
    { url: `${base}${path}`, method: "POST", headers: { Authorization: `Bearer ${token}` }, body, label, timeoutMs },
    async (url, init) => {
      const res = await fetcher(url, init);
      return { ok: res.ok, status: res.status, text: async () => (text = await res.text()) };
    },
  );
  if (answer === null) throw new Error(`${label} failed: ${text === "" ? "empty" : "JSON null"} response body`);
  return answer;
}

// The broker answers 409 app_busy while another change to the app holds its
// lease: a grant, a link, an open or close of the app or of an app linked to
// it (src/routes/deploy.ts takes the lease before it reads or writes
// anything, and /deploy-token revokes any token it minted for the refused
// call). Failing there would fail a deploy over a change that ends in
// seconds, so that one answer is retried: the broker wrote nothing, and the
// same request is safe to send again. Four attempts, 5s, 15s, then 30s
// apart: 50s of waiting covers a holder doing one slow identity-provider read
// under the lease (a grant to a consumer, or a close that includes this app),
// and stays well inside a fresh OIDC token's life. Every other answer, a 409
// for a stopped app or a stale deployment included, fails at once.
// The platform's own host wave waits out a held lease on the same schedule
// (src/hosts.ts HOST_WAVE_BUSY_DELAYS_MS, a copy, since ci/ ships standalone
// and imports nothing from src/, which test/doc-parity.node.test.ts holds to
// this one).
export const BUSY_RETRY_DELAYS_MS = [5_000, 15_000, 30_000];

/** True for the broker's lease refusal: HTTP 409 with the JSON error app_busy. */
export function isBusyRefusal(err) {
  if (err?.status !== 409 || typeof err.body !== "string") return false;
  try {
    return JSON.parse(err.body)?.error === "app_busy";
  } catch {
    return false;
  }
}

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Run `send` (one broker request) and retry it on the lease refusal alone,
 * BUSY_RETRY_DELAYS_MS apart, logging each retry to stderr: never stdout,
 * which the workflow parses (`jq`) for the two callers' answers. Any other
 * failure, and the last busy answer, is thrown as it came.
 *
 * @template T
 * @param {string} label - the request's label, e.g. "deploy-token"
 * @param {() => Promise<T>} send
 * @param {(ms: number) => Promise<void>} [wait] - the pause between attempts; injectable for testing
 * @returns {Promise<T>}
 */
export async function withBusyRetry(label, send, wait = pause) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await send();
    } catch (err) {
      if (!isBusyRefusal(err) || attempt >= BUSY_RETRY_DELAYS_MS.length) throw err;
      const ms = BUSY_RETRY_DELAYS_MS[attempt];
      console.error(`${label}: the broker answered 409 app_busy (another change to this app is in flight); ` +
        `retrying in ${ms / 1000}s (attempt ${attempt + 1} of ${BUSY_RETRY_DELAYS_MS.length + 1})`);
      await wait(ms);
    }
  }
}
