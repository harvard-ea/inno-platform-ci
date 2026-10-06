// Shared "am I the script node was told to run?" guard for every ci/ and
// scripts/ CLI's main block. Lives on its own (not in broker-post.mjs, its
// former home) so scripts/ — which has no reason to depend on the broker
// helper — can import it standalone.
//
// Fixed here: the old broker-post.mjs version compared
// `importMetaUrl === \`file://${process.argv[1]}\`` — a hand-built template
// that breaks for any argv[1] path needing percent-encoding (spaces, etc.):
// file URLs percent-encode such characters, so the template never matches
// and the CLI block silently no-ops. pathToFileURL(...).href performs the
// same encoding Node's own import.meta.url uses, so comparing against that
// is exact.
import { pathToFileURL } from "node:url";

/**
 * True when the module whose `import.meta.url` is passed is the entry point node
 * was invoked with (i.e. run directly, not imported). Callers pass their OWN
 * `import.meta.url` because it is lexically bound to the calling module.
 *
 * @param {string} importMetaUrl - the caller's import.meta.url
 * @returns {boolean}
 */
export function isMainModule(importMetaUrl) {
  if (!process.argv[1]) return false;
  return importMetaUrl === pathToFileURL(process.argv[1]).href;
}

/**
 * Parse a numeric CLI argument the workflow read out of a JSON response with
 * `jq -r`. A missing field reaches the shell as the literal string "null",
 * which is truthy in an argv presence check and NaN through Number(), and
 * JSON.stringify then serialises that NaN as null: the broker answers 400
 * bad_request and the log names the wrong side. Every id the ci/ scripts
 * POST goes through here so the failure is local and says which argument.
 *
 * @param {string} label - the argument's name in the usage line, e.g. "deploymentId"
 * @param {string|undefined} raw - the argv value
 * @returns {number}
 */
export function parseIntegerArg(label, raw) {
  const n = Number(raw);
  if (typeof raw !== "string" || raw.trim() === "" || !Number.isInteger(n)) {
    throw new Error(`invalid ${label} ${JSON.stringify(raw)}: expected an integer (a field missing from the JSON the workflow read reaches the shell as the literal "null")`);
  }
  return n;
}

/**
 * Flatten control bytes out of a value and bound its length, for anything a
 * ci/ script interpolates into a GitHub Actions log line or, especially, into
 * a workflow command.
 *
 * A workflow command (`::warning title=...::`, `::error ...::`) is terminated
 * by a newline, so an author-controlled value carrying one forges a clean
 * second command line in the run's log. Node's JSON.parse error message
 * embeds a snippet of the RAW input, newlines and all, and a package name or
 * an advisory id is read out of the app's own repository before npm or pip
 * has validated anything. Every such interpolation goes through here first.
 *
 * CROSS-BUILD TWIN of `flattenControl` in `src/util.ts`. It cannot import it:
 * ci/ ships standalone to the public mirror repo and imports nothing from
 * src/, by standing constraint (ci/broker-post.mjs's header states the same
 * rule for the broker helper). test/constant-parity.node.test.ts pins the two
 * to the same behaviour. The length bound is this side's own addition,
 * because every caller here is writing exactly one log line, whereas src/
 * leaves the bound to each caller.
 *
 * The character class is written as ESCAPES, never as raw bytes: an editing
 * tool flattened this exact class into literal control bytes on 2026-09-18,
 * where it stayed invisible to tsc and to the whole suite. A scan of the
 * committed bytes is the only instrument that finds that, and
 * test/control-bytes.node.test.ts is that scan.
 *
 * @param {unknown} s - the value to flatten
 * @param {number} [n] - maximum length of the result
 * @returns {string}
 */
export const logSafe = (s, n = 200) => String(s).replace(/[\u0000-\u001f\u007f]+/g, " ").slice(0, n);
