import { readBoundedBytesFrom } from "./bounded-body";
import { errLine } from "./log-text";
import { GATEWAY_KEY_HEADER, PLATFORM_ORIGIN } from "./platform";

// PLATFORM carries Connections v1's /_connections/{name} proxy below. It is
// bound on every current variant (the human-activity touch channel, spec
// 2026-08-18; see env.ts), so the 501 below covers only a gateway deployed
// from a config that predates that binding. An sso-perimeter app therefore
// reaches the platform seam, but carries no caller assertion (the Access path
// mints none; only introspection does), so the platform refuses it with 400
// bad_request rather than this file answering 501. GATEWAY_INTROSPECT_KEY is
// the proof of gateway-hood linkStillLive presents on /_links/check; optional
// on Env because a gateway deployed before the key existed has none, and its
// absence fails that check closed.
// Not Pick<Env, …>: DB/FILES are optional on Env because the function-shaped
// gateway variants don't bind them, but handleStorage is reachable ONLY as
// AppContainer's storage.internal outbound handler — i.e. only on the
// container-shaped deploys, where both always exist. Stating that here keeps
// the narrowing at the one place the invariant actually holds (index.ts's
// outboundByHost registration) instead of scattering `!` through this file.
export type StorageEnv = {
  DB: D1Database;
  FILES: R2Bucket;
  PLATFORM?: Fetcher;
  GATEWAY_INTROSPECT_KEY?: string;
};
type S = StorageEnv;

// Same grammar the platform enforces for a connection name (src/connections/store.ts
// CONN_NAME_RE) — restated rather than imported, same reason as APP_NAME_RE below:
// the gateway builds separately from the platform Worker.
const CONNECTION_NAME_RE = /^[a-z][a-z0-9-]{0,63}$/;
// Hand-written twin of src/routes/connections.ts's CONNECTIONS_FETCH_PATH
// (gateway/ builds separately) — pinned by test/constant-parity.node.test.ts.
const CONNECTIONS_FETCH_PATH = "/_connections/fetch";

// Hand-written twin of src/routes/links.ts's LINKS_CHECK_PATH (gateway/ builds
// separately) — pinned by test/constant-parity.node.test.ts.
const LINK_CHECK_PATH = "/_links/check";

// Per-isolate memo of the platform's answer. A linked-storage call is a hot
// path for a consumer app, and the platform's answer changes only when someone
// revokes a link — 60 s matches the platform's own admin-roster and
// account-status caches and bounds the revocation lag to the same window every
// other control on this platform uses.
const LINK_CHECK_TTL_MS = 60_000;
const linkCheckCache = new Map<string, { live: boolean; at: number }>();

function linkGenerationVar(sourceApp: string): string {
  return `LINK_GEN_${sourceApp.toUpperCase().replace(/-/g, "_")}`;
}

/**
 * Ask the platform whether this deployed link is still live.
 *
 * Returns null in exactly ONE case: this gateway carries no baked generation
 * for the source app (a gateway deployed before R09). The caller treats null
 * as "keep the pre-R09 behavior" so promoting this gateway does not break
 * every already-deployed linked app before its redeploy.
 *
 * Returns false for every other way the question goes unanswered: no PLATFORM
 * binding, no gateway key, a transport failure, or a non-200. Once an app IS
 * carrying a generation, an unanswerable check fails CLOSED. That is the whole
 * point of the control (a revoked link must stop working even when the
 * platform is having a bad day), and it is why the negative is not cached (a
 * blip must not stick for a minute).
 */
async function linkStillLive(env: S, sourceApp: string): Promise<boolean | null> {
  const generation = (env as unknown as Record<string, unknown>)[linkGenerationVar(sourceApp)];
  // Generation first, binding second: a gateway that carries a generation but
  // cannot ask (no binding, no key) must fail CLOSED, uniformly. Testing the
  // binding first made the no-PLATFORM case return null, i.e. ALLOW.
  if (typeof generation !== "string" || generation === "") return null;
  if (!env.PLATFORM) return false;
  const now = Date.now();
  const hit = linkCheckCache.get(generation);
  if (hit && now - hit.at < LINK_CHECK_TTL_MS) return hit.live;
  const key = env.GATEWAY_INTROSPECT_KEY;
  if (!key) {
    console.warn("gateway: linked storage carries a generation but no GATEWAY_INTROSPECT_KEY — refusing");
    return false;
  }
  try {
    const res = await env.PLATFORM.fetch(`${PLATFORM_ORIGIN}${LINK_CHECK_PATH}`, {
      method: "POST",
      headers: { "content-type": "application/json", [GATEWAY_KEY_HEADER]: key },
      body: JSON.stringify({ source_app: sourceApp, generation }),
    });
    if (!res.ok) {
      console.warn(`gateway: link check refused (${res.status}) for ${sourceApp}`);
      return false;
    }
    const body = (await res.json()) as { live?: unknown };
    const live = body?.live === true;
    // Positive and negative answers both memo; only an UNANSWERED check does not.
    linkCheckCache.set(generation, { live, at: now });
    return live;
  } catch (e) {
    console.warn(`gateway: link check failed for ${sourceApp}: ${errLine(e, 120)}`);
    return false;
  }
}

// Per-object upload cap (25 MiB), a DECLARED-length cap: a body must declare
// its length. Production R2's stream put() needs a known length; given a
// stream whose length is not known up front it throws exactly "Provided
// readable stream must have a known length (request/response body or
// readable half of FixedLengthStream)" (cloudflare/workers-sdk issue 6425,
// cloudflare/miniflare issue 506), a fact the R2 documentation and issue
// history already establish as of 2026-09-21; the experiment planned in
// docs/superpowers/plans/2026-09-21-open-31-33-v0.14.21.md is confirmation of
// it, not the basis for it. A chunked PUT carries no content-length, so
// before this fix it reached FILES.put and died there, answered as 500
// storage_error; no app has ever completed a lengthless upload through this
// gateway. The PUT arm below now refuses one explicitly, with 411, decided
// from the header alone before any R2 call. That "from the header alone" is
// deliberate: Miniflare's R2 may accept an unknown-length stream where
// production R2 does not (miniflare issue 506 is about exactly that gap), so
// the 411 must never be decided by what a local put happens to do.
// Exported so the docs parity suite can read the number it documents rather
// than restating it; nothing in the gateway build imports it.
export const MAX_UPLOAD_BYTES = 25 * 1024 * 1024;

// Must match src/links.ts linkBindingFor — the gateway builds separately from
// the platform Worker, so the derivation is restated rather than imported. A
// test asserts the two agree.
const APP_NAME_RE = /^[a-z][a-z0-9-]{2,28}$/;
export function linkBindingFor(sourceApp: string): string {
  return `LINKED_${sourceApp.toUpperCase().replace(/-/g, "_")}`;
}

/**
 * Resolve `/_storage/linked/{app}/...` to the D1 binding the platform injected
 * for that link, or null when no such link is deployed.
 *
 * The presence of the binding IS the authorization: it exists only because the
 * platform templated it into this gateway's config at deploy time, having
 * checked same-owner and membership containment. The container cannot conjure a
 * binding, so a request naming an unlinked app finds nothing.
 */
function resolveLinkedDb(env: S, sourceApp: string): D1Database | null {
  if (!APP_NAME_RE.test(sourceApp)) return null;
  // Linked bindings are named after the SOURCE app, so they cannot appear in the
  // static Env type — look them up dynamically rather than widening Env with an
  // index signature (which would weaken every other binding's typing).
  const candidate = (env as unknown as Record<string, unknown>)[linkBindingFor(sourceApp)];
  // Duck-type rather than instanceof: D1Database is not a constructible global.
  return candidate && typeof (candidate as D1Database).prepare === "function"
    ? (candidate as D1Database)
    : null;
}

// Cap for the one JSON body this file reads: the `{ sql, params? }` an app
// sends over the service binding. 4 MiB is the largest body the platform
// BUFFERS anywhere (the /mcp entry streams up to the same number), which
// makes it the one value that bounds what a single request can buffer in the
// gateway isolate with no possibility of refusing a call that works today.
// The realistic large case here is a bulk insert, nowhere near it. The
// tighter caps elsewhere are for bodies of a known small shape and are not
// the precedent for this one: the house JSON seam is 64 KiB
// (src/routes/read-json.ts DEFAULT_MAX_BODY_BYTES) and the activity peek is
// 256 KiB (activity.ts PEEK_MAX_BYTES).
//
// The 25 MiB file PUT (MAX_UPLOAD_BYTES above) is the deliberate exception
// and not a counterexample: that body is handed straight to FILES.put and is
// never held in the isolate, so its number is a per-object storage limit
// rather than a memory one.
// Exported for the same reason as MAX_UPLOAD_BYTES above.
export const MAX_SQL_BODY_BYTES = 4 * 1024 * 1024;

// R2 caps list() at 1000 keys and sets `truncated` with a cursor, so a single
// call silently returns a PARTIAL listing that an app author reads as "these
// are all my files". The files GET pages with this bound, sized like the
// platform's own R2 sweeps (support-bundle/exports run 10 pages), each list()
// being one subrequest against the container-outbound invocation budget:
// 10 x 1000 keys covers any sane app bucket. If the cap is ever hit, the
// response SAYS so (`truncated: true`) rather than passing a partial listing
// off as complete; an app needing more than 10k keys listed should track its
// keys in D1, not walk the bucket. Exported for the docs parity suite, like
// the two caps above.
export const MAX_LIST_PAGES = 10;

type SqlOp = "query" | "execute";

// The SQL surface, once, for the app's own database and for a linked one:
// read the body, refuse a missing `sql`, bind, and shape the result per op.
// The linked branch deliberately serves the same API as the own-database
// branch (an author who can read their own D1 can read a linked one without
// learning anything new), so the request and response shapes live here and
// a change to either lands in one place, not four.
async function runSql(db: D1Database, op: SqlOp, request: Request): Promise<Response> {
  const body = await readJson<{ sql: string; params?: unknown[] }>(request, MAX_SQL_BODY_BYTES);
  if (!body?.sql) return json({ error: "bad_request" }, 400);
  const stmt = db.prepare(body.sql).bind(...(body.params ?? []));
  if (op === "query") {
    const { results } = await stmt.all();
    return json({ results });
  }
  const r = await stmt.run();
  return json({ changes: r.meta.changes ?? 0, lastRowId: r.meta.last_row_id ?? null });
}

export async function handleStorage(request: Request, env: S): Promise<Response> {
  try {
    const url = new URL(request.url);
    const path = url.pathname;
    const m = request.method;

    const ownMatch = path.match(/^\/_storage\/sql\/(query|execute)$/);
    // AWAITED, not returned as a promise, so a D1 rejection (bad SQL) is
    // caught by this function's catch and answered as storage_error 500.
    if (ownMatch && m === "POST") return await runSql(env.DB, ownMatch[1] as SqlOp, request);
    // Cross-app data links (migration 0028). Same query/execute surface as the
    // app's own database (runSql), scoped to a source app it has a deployed
    // link to.
    const linkMatch = path.match(/^\/_storage\/linked\/([^/]+)\/sql\/(query|execute)$/);
    if (linkMatch && m === "POST") {
      const [, sourceApp, op] = linkMatch;
      const linkedDb = resolveLinkedDb(env, sourceApp);
      if (!linkedDb) {
        return json({
          error: "not_linked",
          detail:
            `No deployed data link to "${sourceApp}". Create one with the link_app_data MCP tool ` +
            "(same owner only), then redeploy this app — links are bound at deploy time.",
        }, 404);
      }
      // The binding proves the platform templated this link at DEPLOY time.
      // It does not prove the link is still live: revoking one stamped
      // revoked_at in D1 and left the deployed binding working until the
      // consumer happened to redeploy (review F04 / M-7). Ask.
      const live = await linkStillLive(env, sourceApp);
      if (live === false) {
        return json({
          error: "link_revoked",
          detail:
            `The data link to "${sourceApp}" is no longer live, or the platform could not confirm it. ` +
            "Ask the source app's owner to re-link, then redeploy this app.",
        }, 403);
      }
      return await runSql(linkedDb, op as SqlOp, request);
    }
    if (path === "/_storage/files" && m === "GET") {
      // Paged, never one call: see MAX_LIST_PAGES above for why, and for what
      // `truncated` means when the bound is reached.
      const keys: string[] = [];
      let cursor: string | undefined;
      let truncated = false;
      for (let page = 0; page < MAX_LIST_PAGES; page++) {
        const list = await env.FILES.list(cursor ? { cursor, limit: 1000 } : { limit: 1000 });
        for (const o of list.objects) keys.push(o.key);
        cursor = list.truncated ? list.cursor : undefined;
        if (!cursor) break;
        if (page === MAX_LIST_PAGES - 1) truncated = true;
      }
      return json(truncated ? { keys, truncated } : { keys });
    }
    const fileMatch = path.match(/^\/_storage\/files\/(.+)$/);
    if (fileMatch) {
      const key = decodeURIComponent(fileMatch[1]);
      if (m === "PUT") {
        const len = request.headers.get("content-length");
        if (!len) return json({ error: "length_required" }, 411);
        if (Number(len) > MAX_UPLOAD_BYTES) return json({ error: "too_large" }, 413);
        await env.FILES.put(key, request.body);
        return json({ key });
      }
      if (m === "GET") {
        const obj = await env.FILES.get(key);
        if (!obj) return json({ error: "not_found" }, 404);
        return new Response(obj.body, { status: 200 });
      }
      if (m === "DELETE") { await env.FILES.delete(key); return json({ deleted: true }); }
    }
    if (path.startsWith("/_connections/") && m === "POST") {
      // Per-user backend credentials (APP-CONTRACT Connections). The container
      // echoes the gateway-injected X-Caller-Assertion; identity travels ONLY in
      // that platform-signed token — this outbound handler cannot see the inbound
      // request, and every header here is container-authored (untrusted).
      // Method-gated like every sibling route above (path+method in one
      // condition): the container always POSTs here, so any other verb should
      // fall through to the same unknown_storage_route 404 as an unmatched path,
      // not be silently forwarded to the platform as a hardcoded POST.
      if (!env.PLATFORM) return json({ error: "connections_unavailable" }, 501);
      const name = path.slice("/_connections/".length);
      if (!CONNECTION_NAME_RE.test(name)) return json({ error: "bad_connection_name" }, 400);
      // AWAITED, not returned as a promise, for the same reason runSql is
      // (see its call site above): a binding call that REJECTS is then caught
      // by this function's catch and answered as storage_error 500, which is
      // this file's contract with the container. Returned unawaited the
      // rejection escaped handleStorage entirely and the app saw a
      // runtime-level failure with no body it could read.
      return await env.PLATFORM.fetch(`${PLATFORM_ORIGIN}${CONNECTIONS_FETCH_PATH}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ assertion: request.headers.get("x-caller-assertion") ?? "", connection: name }),
      });
    }
    return json({ error: "unknown_storage_route" }, 404);
  } catch (e) {
    // The one errLine whose output leaves the gateway: this `detail` is read
    // by the app's own storage client, so the flattening is not only about
    // keeping a log line on one line.
    return json({ error: "storage_error", detail: errLine(e) }, 500);
  }
}

// Bounded, so a body larger than the cap is refused before it is buffered
// rather than after. An over-cap body lands on the same null, and therefore
// the same 400 bad_request, as an unparseable one: the caller is the app's
// own container over a service binding, not a browser, and there is nothing
// it can do about either answer that a distinct status would help with.
async function readJson<T>(req: Request, maxBytes: number): Promise<T | null> {
  const bytes = await readBoundedBytesFrom(req, maxBytes);
  if (!bytes) return null;
  try { return JSON.parse(new TextDecoder().decode(bytes)) as T; } catch { return null; }
}
function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
