#!/usr/bin/env node
// Hands a function app's Worker bundle to the platform, which uploads the
// Worker itself (v0.17.0). The app-build job, which holds no credential of any
// kind, bundles the app with the pinned wrangler's `deploy --dry-run
// --outfile`: one regular file, worker.form, holding the exact multipart
// upload form wrangler would have sent (every module, with its content type).
// It pins that file's sha256 as a job output, which only the job that declares
// it can write, from this reusable workflow the caller cannot edit. The deploy
// job downloads the file into a directory of its own under the runner's temp
// and runs this script, which reads it once, checks those bytes against the
// pinned digest, and POSTs them unchanged to the broker's /deploy-bundle. The
// broker authenticates the OIDC token before it reads a byte of the body,
// validates the form, stages it under the app and the deployment, and answers
// the digest it computed itself. Finalize then names that digest, and the
// platform uploads the Worker under the app's lease, with bindings it writes
// itself. No Cloudflare credential is involved on this side.
//
// Usage:
//   node ci/deploy-bundle.mjs <brokerUrl> <app> <deploymentId> <token> <bundleDir> <expectedSha256>
//   node ci/deploy-bundle.mjs --digest <bundleDir>
//   node ci/deploy-bundle.mjs --verify <bundleDir> <expectedSha256>
// The first form is the deploy job's hand-over. It prints the digest the
// platform staged, `sha256:<hex>`, on stdout, which the Finalize step sends as
// `bundle`, and every message on stderr. It does not retry: a 409 is final,
// and a 5xx or no answer within HAND_OVER_TIMEOUT_MS means re-running the
// job. The second form is the app-build job's check of the bundle it just
// built: it reads the directory as the hand-over will (one regular file named
// worker.form, within the size cap) and prints the file's sha256 hex on
// stdout, which that job pins as its output. The third is the deploy job's
// check of the download, right after it lands and before the broker records
// a deployment: every local check the hand-over makes (verifyBundle), and
// nothing sent. `token` is the GitHub Actions OIDC token (verified
// server-side).

import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { refusalText, reportRefusal } from "./broker-post.mjs";
import { isMainModule, logSafe, parseIntegerArg } from "./cli.mjs";

// The largest form the platform takes, before compression: its own memory
// bound (a finalize holds up to about four copies of the form in one isolate
// at once, and the hand-over about three; src/function-bundle.ts counts
// them), not Cloudflare's script limit, which Cloudflare measures after
// compression and enforces itself at upload. Checked here twice, so an author
// learns it from the build on every push rather than from a refused release:
// in app-build, as soon as the bundle exists, and again on the bytes this
// script hands over. test/doc-parity.node.test.ts pins it to src/'s
// MAX_BUNDLE_BYTES; it is NOT imported from there, because ci/ ships
// standalone in the public mirror and imports nothing from src/ on purpose.
export const MAX_BUNDLE_BYTES = 16 * 1024 * 1024;

// The one file a bundle directory holds: the name app-build's --outfile
// writes, and the only name the upload-artifact step publishes.
export const BUNDLE_FILE = "worker.form";

// How long the hand-over waits for the platform's answer: room to send a
// bundle at the cap over a slow runner link, and for the platform to read,
// check and stage it.
export const HAND_OVER_TIMEOUT_MS = 120_000;

const SHA256_HEX = /^[0-9a-f]{64}$/;

// RFC 2046's boundary characters without the space, which it allows only
// before the end and which would have to be quoted in the Content-Type
// header. wrangler's form uses undici's boundary (`----formdata-undici-0`
// and eleven digits), well inside this.
const BOUNDARY = /^[0-9A-Za-z'()+_,./:=?-]{1,70}$/;

/**
 * Read the bundle directory the way both jobs must: it holds exactly one
 * entry, a regular file named worker.form (never a link, which is refused
 * without being followed), no larger than MAX_BUNDLE_BYTES. The file is read
 * ONCE, from the descriptor that was checked, and the digest is of those
 * bytes, so the bytes hashed are the bytes sent. Throws with a message for
 * the run's log on any other shape.
 *
 * @param {string} dir
 * @returns {{ bytes: Buffer, sha256: string }}
 */
export function readBundle(dir) {
  let st;
  try { st = lstatSync(dir); } catch (e) {
    throw new Error(`no bundle directory at ${dir} (${logSafe(e?.code ?? e, 40)}): the app-build job's bundle was not downloaded`);
  }
  if (!st.isDirectory()) throw new Error(`${dir} is not a directory (a link or a file in its place is refused)`);
  const entries = readdirSync(dir).sort();
  if (entries.length !== 1 || entries[0] !== BUNDLE_FILE) {
    throw new Error(
      `the bundle directory must hold ${BUNDLE_FILE} and nothing else; it holds ` +
        `${entries.length === 0 ? "nothing" : entries.map((e) => JSON.stringify(logSafe(e, 80))).join(", ")}`,
    );
  }
  const path = join(dir, BUNDLE_FILE);
  // O_NOFOLLOW: a link in the file's place fails the open itself, so nothing
  // can swap one in between a check and the read.
  let fd;
  try { fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW); } catch (e) {
    throw new Error(`${BUNDLE_FILE} could not be opened as a regular file (${logSafe(e?.code ?? e, 40)}); a link is refused`);
  }
  try {
    const fst = fstatSync(fd);
    if (!fst.isFile()) throw new Error(`${BUNDLE_FILE} is not a regular file`);
    if (fst.size > MAX_BUNDLE_BYTES) throw tooLarge(fst.size);
    const bytes = readFileSync(fd);
    // The bytes actually read, too: the file can grow between the stat and
    // the read, and the cap is on what is sent.
    if (bytes.length > MAX_BUNDLE_BYTES) throw tooLarge(bytes.length);
    if (bytes.length === 0) throw new Error(`${BUNDLE_FILE} is empty`);
    return { bytes, sha256: createHash("sha256").update(bytes).digest("hex") };
  } finally {
    closeSync(fd);
  }
}

const MIB = 1024 * 1024;
function tooLarge(size) {
  return new Error(
    `the app Worker's bundle is ${size} bytes; the platform takes at most ${MAX_BUNDLE_BYTES} (${MAX_BUNDLE_BYTES / MIB} MiB) ` +
      "before compression. Cloudflare's own script limit applies after compression as well. Make the bundle smaller: " +
      "drop large imported files or dependencies the Worker does not use.",
  );
}

/**
 * The multipart boundary, read from the form's first line, which is
 * `--<boundary>` and a CRLF. wrangler writes no Content-Type beside the
 * file, so this line is the only place the boundary is recorded.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function boundaryOf(bytes) {
  // 2 for the dashes, 70 for the longest boundary RFC 2046 allows.
  const head = Buffer.from(bytes.subarray(0, 74)).toString("latin1");
  const end = head.indexOf("\r\n");
  const boundary = end > 2 && head.startsWith("--") ? head.slice(2, end) : "";
  if (!BOUNDARY.test(boundary)) {
    throw new Error(`${BUNDLE_FILE} does not start with a multipart boundary line, so it is not the form wrangler writes`);
  }
  return boundary;
}

/**
 * The hand-over's local checks, in its order: an expected digest that is
 * empty or not a sha256 (a job output sourced from a skipped step is "", and
 * "nothing to compare" must never read as "matches"), a directory of any
 * other shape, a file over the cap, bytes whose digest is not the expected
 * one, and a file with no boundary line. The deploy job runs them on the
 * download before the broker records a deployment (--verify), and the
 * hand-over runs them again on the bytes it sends. Returns those bytes and
 * the form's boundary; throws with a message for the run's log.
 *
 * @param {string} dir - the directory the bundle was downloaded into
 * @param {string} expected - the sha256 hex app-build pinned as its output
 * @returns {{ bytes: Buffer, boundary: string }}
 */
export function verifyBundle(dir, expected) {
  if (typeof expected !== "string" || !SHA256_HEX.test(expected)) {
    throw new Error(
      expected
        ? `the pinned bundle digest ${JSON.stringify(logSafe(expected, 80))} is not a sha256; refusing the bundle`
        : "app-build recorded no sha256 for the app Worker's bundle; refusing the artifact rather than handing over an unverified one",
    );
  }
  const { bytes, sha256 } = readBundle(dir);
  // The DIGEST is what makes these bytes trustworthy, not the artifact name:
  // app-owned jobs in the calling repo share the run's artifact namespace and
  // can upload their own file under this name once app-build finishes.
  if (sha256 !== expected) {
    throw new Error(`the downloaded bundle is not the one app-build built (sha256 ${sha256} != ${expected})`);
  }
  return { bytes, boundary: boundaryOf(bytes) };
}

/**
 * POST the bundle's bytes to `${base}/deploy-bundle?app=<app>&deployment_id=<n>`,
 * authenticated with the GitHub Actions OIDC token, and return the digest the
 * platform staged (`sha256:<hex>`).
 *
 * Every local refusal (verifyBundle) comes before the request. The platform's
 * answer must name the same digest, or the platform staged something other
 * than what app-build built. No answer within `timeoutMs` (default
 * HAND_OVER_TIMEOUT_MS) ends the request, so a platform that never answers
 * cannot hold the job, and the app's deploy, until the job's own timeout.
 *
 * @param {object} req
 * @param {string} req.base - broker base URL
 * @param {string} req.app
 * @param {number} req.deploymentId - the deployment /deploy-token started
 * @param {string} req.token - GitHub Actions OIDC token
 * @param {string} req.dir - the directory the bundle was downloaded into
 * @param {string} req.expected - the sha256 hex app-build pinned as its output
 * @param {number} [req.timeoutMs] - how long to wait for the answer; HAND_OVER_TIMEOUT_MS when absent
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} [fetcher]
 *   - injectable for testing; defaults to global fetch
 * @returns {Promise<string>} `sha256:<hex>`
 * @throws {Error & { status?: number, body?: string }} with a message for the run's log
 */
export async function handOver({ base, app, deploymentId, token, dir, expected, timeoutMs = HAND_OVER_TIMEOUT_MS }, fetcher = fetch) {
  const { bytes, boundary } = verifyBundle(dir, expected);
  const query = `app=${encodeURIComponent(app)}&deployment_id=${encodeURIComponent(String(deploymentId))}`;
  let res;
  let text;
  try {
    res = await fetcher(`${base}/deploy-bundle?${query}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": `multipart/form-data; boundary=${boundary}`,
        "Content-Length": String(bytes.length),
      },
      body: bytes,
      signal: AbortSignal.timeout(timeoutMs),
    });
    text = await res.text();
  } catch (e) {
    if (e?.name === "TimeoutError") {
      throw new Error(`deploy-bundle failed: the platform did not answer within ${timeoutMs / 1000} s; re-run the job`);
    }
    throw e;
  }
  if (!res.ok) {
    // The refusal's own message names the rule and the fix (a module type the
    // platform does not take, the size cap, a deployment that is not this
    // app's latest), so it is what the log shows, read as jsonRequest reads
    // every broker refusal (refusalText: `<error>: <message>`, flattened, as
    // it can quote an author's module name), the status and the body beside
    // it for the CLI's report.
    throw Object.assign(new Error(`deploy-bundle failed (${res.status}): ${refusalText(text)}`), { status: res.status, body: text });
  }
  let answer;
  try { answer = JSON.parse(text); } catch { answer = undefined; }
  const staged = `sha256:${expected}`;
  if (answer?.bundle !== staged) {
    throw new Error(
      `deploy-bundle failed: the platform staged ${logSafe(JSON.stringify(answer?.bundle ?? null), 100)}, ` +
        `not the bundle app-build built (${staged})`,
    );
  }
  return staged;
}

if (isMainModule(import.meta.url)) {
  const HAND_OVER = "Usage: node ci/deploy-bundle.mjs <brokerUrl> <app> <deploymentId> <token> <bundleDir> <expectedSha256>";
  const DIGEST = "       node ci/deploy-bundle.mjs --digest <bundleDir>";
  const VERIFY = "       node ci/deploy-bundle.mjs --verify <bundleDir> <expectedSha256>";
  const USAGE = `${HAND_OVER}\n${DIGEST}\n${VERIFY}`;
  try {
    const argv = process.argv.slice(2);
    if (argv[0] === "--digest") {
      if (argv.length !== 2 || !argv[1]) throw new Error(USAGE);
      console.log(readBundle(argv[1]).sha256);
    } else if (argv[0] === "--verify") {
      // The expected digest is verifyBundle's to refuse, as in the hand-over.
      if (argv.length !== 3 || !argv[1]) throw new Error(USAGE);
      verifyBundle(argv[1], argv[2]);
      console.error(`deploy-bundle: the downloaded bundle is the one app-build built (sha256 ${argv[2]})`);
    } else {
      // The expected digest is NOT checked for presence here: an empty one is
      // handOver's refusal to make, with its own message, so that the case a
      // skipped app-build step produces reads as what it is.
      const [base, app, deploymentId, token, dir, expected] = argv;
      if (!base || !app || !deploymentId || !token || !dir || argv.length !== 6) throw new Error(USAGE);
      const staged = await handOver({
        base, app, deploymentId: parseIntegerArg("deploymentId", deploymentId), token, dir, expected,
      });
      console.error(`deploy-bundle: the platform staged ${staged}`);
      console.log(staged);
    }
  } catch (err) {
    // A plain line, then an annotation, so the refusal shows on the run's
    // summary: the author no longer sees wrangler's own output from a
    // deploy, and this message is the platform's word on why the bundle was
    // not taken. ci/broker-post.mjs reportRefusal, as the token, finalize and
    // SBOM CLIs report one: the plain line keeps the whole message in the
    // step log (the annotation keeps ANNOTATION_WHAT_MAX characters of it),
    // and a broker refusal's code is the annotation's what and its sentence
    // the fix. A local refusal has no fix of its own beyond what it says.
    // Every message is already flattened where it quotes anything from
    // outside this script; logSafe and annotate flatten it again, which is
    // what keeps that true for a message added later.
    const message = String(err?.message ?? err);
    if (message.startsWith("Usage:")) {
      console.error(message);
    } else {
      reportRefusal(err, { label: "deploy-bundle", title: "App Worker bundle", fix: "" });
    }
    process.exitCode = 1;
  }
}
