// Shared brokerPost() helper for the ci/ scripts: the "POST JSON to a broker
// endpoint" call every ci/ script that POSTs to the broker used to open with.
// Which of those callers ship in the public mirror is scripts/publish-mirror.sh's
// manifest (test-enforced), not a list kept here. Each did exactly the same thing: POST a JSON body to
// a broker endpoint with the GitHub Actions OIDC token as a bearer, read the
// response as text FIRST (so a non-2xx, non-JSON body — e.g. an HTML 500
// page — surfaces the real status + body instead of a raw JSON parse error),
// throw on !res.ok with a 200-char snippet, and JSON.parse the body on
// success. Only the endpoint path, the request-body shape, and the error
// label differ per caller, so those are the parameters; everything else is
// identical.
//
// (The isMainModule() CLI-entry-point guard used to live here too; it moved
// to ci/cli.mjs so scripts/ — which has no reason to depend on this broker
// helper — can import it standalone.)
//
// Zero imports on purpose: brokerPost uses the global fetch (injectable for
// tests), so nothing that imports it takes on a transitive dependency.

/**
 * POST a JSON body to `${base}${path}` on the platform broker, authenticated
 * with the GitHub Actions OIDC token, and return the parsed JSON response.
 *
 * Reads the body as text first so a non-2xx, non-JSON body (e.g. an HTML 500
 * page) surfaces the real status + body instead of a raw JSON parse error.
 *
 * @param {object} req
 * @param {string} req.base - broker base URL, e.g. "https://inno-platform.example.workers.dev"
 * @param {string} req.path - endpoint path beginning with "/", e.g. "/deploy-complete"
 * @param {string} req.label - error-message prefix, e.g. "deploy-complete" -> "deploy-complete failed (…)"
 * @param {string} req.token - GitHub Actions OIDC token
 * @param {any} req.body - request body, JSON.stringify'd as-is
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} [fetcher]
 *   - injectable for testing; defaults to global fetch
 * @returns {Promise<any>} the parsed JSON response body
 */
export async function brokerPost({ base, path, label, token, body }, fetcher = fetch) {
  const res = await fetcher(`${base}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  });
  // Read the body as text first so a non-2xx, non-JSON body surfaces the real
  // status + body instead of a raw JSON parse error.
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`${label} failed (${res.status}): ${text.slice(0, 200)}`);
  }
  return JSON.parse(text);
}
