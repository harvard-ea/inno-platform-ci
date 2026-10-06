// MCP mode: the gateway as an OAuth 2.1 Resource Server.
//
// mcp-type apps have NO Cloudflare Access application (an MCP client cannot
// complete an interactive Access login), so this file replaces the Access-JWT
// check with a bearer-token check. Everything downstream is unchanged: the same
// AccessIdentity flows into sanitizeAndInject, so the app still receives only
// spoof-proof X-Forwarded-* headers and still implements no authentication —
// APP-CONTRACT R3 holds for mcp apps exactly as it does for the other types.
//
// The platform's access tokens are OPAQUE (workers-oauth-provider encrypts the
// grant into them), so they cannot be verified locally. The gateway asks the
// platform over the PLATFORM service binding.
//
// One introspection per token per isolate: positive results are cached in a
// module-scope Map, with a TTL bounded by both the token's own remaining
// lifetime and MAX_CACHE_SECONDS. After the first request the hot path costs no
// subrequest, which is what makes opaque tokens as cheap here as a
// locally-verified JWT would have been.
//
// The cache is a Map, deliberately NOT the Workers Cache API: `caches.default`
// is shared across every Worker on the zone (the reason Workers-for-Platforms
// offers isolated caches for its "untrusted" mode), and this platform runs app
// code as ordinary Workers on the same zone. A co-resident app author could
// pre-plant an entry under a key they compute from the (public) resource + any
// token and forge an identity for another app's gateway. A module-scope Map is
// private to this isolate — unreachable from any other Worker — so a poisoned
// entry is impossible.

import type { Env } from "./env";
import type { AccessIdentity } from "./access";
import { GROUP_PREFIX } from "./access";
import { errLine, hex } from "./log-text";
import { GATEWAY_KEY_HEADER, PLATFORM_ORIGIN } from "./platform";

// Upper bound on how long a positive introspection is reused. This is the
// revocation lag: a grant revoked at the platform keeps working in an already-
// warm isolate for at most this long. 60s is short next to the 24h Access
// session the other app types run with, so this is a tightening, not a loosening.
const MAX_CACHE_SECONDS = 60;

// Bound the isolate's memory. Map preserves insertion order, so eviction past
// this drops the oldest entry — a coarse LRU that is fine for a per-isolate,
// short-TTL cache. Far above any single app's realistic concurrent-token count.
const MAX_CACHE_ENTRIES = 1000;

interface IntrospectionResponse {
  active: boolean;
  email?: string;
  groups?: string[];
  service?: boolean;
  expires_in?: number;
  // Connections v1 (Task 8, src/mcp/app-tokens.ts): a short-TTL (300s) signed
  // statement of this caller's identity, minted platform-side and cached here
  // right along with the rest of the introspection body. That's safe because
  // this cache's own TTL is bounded at MAX_CACHE_SECONDS (60s) — strictly less
  // than the assertion's 300s lifetime — so a cached assertion is always still
  // within its validity window when reused.
  caller_assertion?: string;
}

// The introspection cache, private to this isolate. Keyed by the hex digest
// (see cacheKeyFor); value carries an absolute expiry so a stale entry is never
// honored past its own TTL even if the isolate outlives it.
const introspectionCache = new Map<string, { body: IntrospectionResponse; expiresAt: number }>();

function cacheGet(key: string, now: number): IntrospectionResponse | null {
  const entry = introspectionCache.get(key);
  if (!entry) return null;
  if (entry.expiresAt <= now) { introspectionCache.delete(key); return null; }
  return entry.body;
}

function cacheSet(key: string, body: IntrospectionResponse, ttlSeconds: number, now: number): void {
  if (introspectionCache.size >= MAX_CACHE_ENTRIES) {
    const oldest = introspectionCache.keys().next().value;
    if (oldest !== undefined) introspectionCache.delete(oldest);
  }
  introspectionCache.set(key, { body, expiresAt: now + ttlSeconds * 1000 });
}

// RFC 9728 §3.1: the metadata document lives under this prefix on the RESOURCE's
// own origin, with the resource's path component INSERTED after it. Our resource
// is `https://inno-{app}.{domain}/mcp`, so the spec-correct URL is
// `/.well-known/oauth-protected-resource/mcp`. Clients differ on this in
// practice, so `isProtectedResourceRequest` accepts the bare prefix too and the
// challenge advertises the spec-correct form.
export const PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource";

// The path-inserted form for a resource whose path is `resourcePath` (e.g.
// "/mcp"). Falls back to the bare prefix for an origin-only resource.
function protectedResourcePathFor(resourcePath: string): string {
  return resourcePath && resourcePath !== "/"
    ? `${PROTECTED_RESOURCE_PATH}${resourcePath}`
    : PROTECTED_RESOURCE_PATH;
}

// Accept either spelling: the bare prefix, or the prefix plus this resource's
// path. Deliberately NOT a blanket prefix match — an unrelated
// `/.well-known/oauth-protected-resource/other` must not be served this app's
// metadata.
export function isProtectedResourceRequest(env: Env, path: string): boolean {
  if (path === PROTECTED_RESOURCE_PATH) return true;
  let resourcePath = "";
  try { resourcePath = new URL(env.OAUTH_RS_RESOURCE ?? "").pathname; } catch { return false; }
  return path === protectedResourcePathFor(resourcePath);
}

export interface McpAuthResult {
  identity: AccessIdentity;
  // Set when the caller presented the platform's health-probe bearer, which has
  // no user identity. The caller restricts it to GET /healthz.
  service: boolean;
}

// RFC 6750 §2.1: credentials go in `Authorization: Bearer <token>`. Deliberately
// header-only — no query-parameter fallback, which RFC 6750 §5.3 warns against
// (tokens leak into logs and Referer headers) and which the protected-resource
// metadata's bearer_methods_supported already declares we don't accept.
export function bearerToken(req: Request): string | null {
  const raw = req.headers.get("authorization");
  if (!raw) return null;
  // Case-INSENSITIVE scheme: RFC 7235 §2.1 defines the auth-scheme token as
  // case-insensitive, and RFC 6750's `Bearer` inherits that. A client sending
  // `authorization: bearer <token>` is spec-compliant and must not get an
  // undiagnosable 401.
  const m = /^Bearer +([^\s]+)$/i.exec(raw.trim());
  return m ? m[1] : null;
}

// Cache key: a hash, never the token itself. The hash input is a JSON array
// rather than a delimiter-joined string, so no separator has to be chosen or
// defended: two different (resource, token) pairs can never serialize
// identically, whatever characters they contain. Including the RESOURCE keeps
// two apps' entries distinct even though the cache is now per-isolate.
async function cacheKeyFor(token: string, resource: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify([resource, token])));
  return hex(digest);
}

// Ask the platform whether this token is live and who it belongs to. Fails
// CLOSED on every failure mode — a non-200, a thrown binding call, or a
// non-JSON body all resolve to {active:false}, so the caller answers the
// recoverable 401 challenge (never a 500, which an MCP client treats as fatal
// and does not retry).
// gateway/ builds separately from src/ and cannot import it — this is a
// hand-written twin of src/routes/mcp-introspect.ts's APP_INTROSPECT_PATH,
// pinned by test/constant-parity.node.test.ts (TOUCH_PATH-style).
const APP_INTROSPECT_PATH = "/app-introspect";

// Takes the binding, not Env, the way activity.ts's sendTouch does: the
// caller has already narrowed env.PLATFORM, so no `!` is needed here.
async function introspectViaPlatform(
  platform: Fetcher, gatewayKey: string | undefined, token: string, resource: string,
): Promise<IntrospectionResponse> {
  try {
    const res = await platform.fetch(`${PLATFORM_ORIGIN}${APP_INTROSPECT_PATH}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        // Proof that this caller is a gateway. The platform mints a
        // caller_assertion — a credential that opens /_connections/fetch —
        // only for a caller holding this, because /app-introspect is publicly
        // reachable and the service binding is routing, not authentication.
        // Omitted entirely when unprovisioned; the platform then withholds
        // the caller assertion unless its admin switch is explicitly false
        // (the cutover override), so a keyless gateway loses Connections
        // until it is redeployed with the key. It loses the idle clock with
        // it: index.ts's touch fires only when the identity carries an
        // assertion, so an MCP app in real use stops advancing its clock and
        // the lifecycle engine warns and then stops it. One redeploy restores
        // both.
        ...(gatewayKey ? { [GATEWAY_KEY_HEADER]: gatewayKey } : {}),
      },
      body: JSON.stringify({ token, resource }),
    });
    if (!res.ok) {
      console.warn(`gateway: introspection failed (${res.status})`);
      return { active: false };
    }
    return (await res.json()) as IntrospectionResponse;
  } catch (e) {
    console.warn(`gateway: introspection threw: ${errLine(e, 120)}`);
    return { active: false };
  }
}

// Resolve a bearer token to an identity, using (and populating) the per-isolate
// cache. Returns null for any invalid/expired/foreign token.
export async function authenticateMcp(
  env: Env, req: Request, resource: string,
): Promise<McpAuthResult | null> {
  const token = bearerToken(req);
  if (!token) return null;
  // A mis-templated gateway with no resource must refuse locally, not lean on
  // the platform rejecting an empty resource across a gateway/platform version
  // skew. Also keeps every such gateway out of a shared `resource=""` key space.
  if (!resource) {
    console.error("gateway: OAUTH_RS mode without OAUTH_RS_RESOURCE — refusing all requests");
    return null;
  }
  if (!env.PLATFORM) {
    // Misconfiguration (an mcp gateway deployed without its service binding).
    // Fail closed rather than serve an app with no identity boundary at all.
    console.error("gateway: OAUTH_RS mode without a PLATFORM service binding — refusing all requests");
    return null;
  }

  const now = Date.now();
  const key = await cacheKeyFor(token, resource);
  let body = cacheGet(key, now);

  if (!body) {
    body = await introspectViaPlatform(env.PLATFORM, env.GATEWAY_INTROSPECT_KEY, token, resource);
    // Only positive results are cached, and only when they have real remaining
    // life — caching an already-expired token (expires_in <= 0) would honor it
    // for up to the 1s TTL floor. Negatives are never cached: a just-granted
    // token must not keep failing, and an invalid token is not a hot path.
    if (body.active) {
      const remaining = body.expires_in ?? MAX_CACHE_SECONDS;
      if (remaining > 0) {
        const ttl = Math.max(1, Math.min(MAX_CACHE_SECONDS, remaining));
        cacheSet(key, body, ttl, now);
      }
    }
  }

  if (!body.active) return null;
  // A positive result with no user identity is only meaningful as the health
  // probe's service credential. Never inject an empty/anonymous identity as a
  // person — the perimeter must not depend on the platform always sending an
  // email for a real user.
  const email = typeof body.email === "string" ? body.email : "";
  if (!email && body.service !== true) {
    console.warn("gateway: rejecting active introspection with no email and no service flag");
    return null;
  }
  // Re-filter groups to the inno- prefix, matching verifyAccessJwt (access.ts)
  // and the dev path — one invariant, now three producers. The gateway is
  // version-pinned per app (gateway_ref) while the platform ships from main, so
  // "the platform already filters" is a cross-version assumption, not a local
  // guarantee; enforce it here too.
  const groups = (Array.isArray(body.groups) ? body.groups : [])
    .filter((g): g is string => typeof g === "string" && g.startsWith(GROUP_PREFIX));
  const identity: AccessIdentity = { email, groups };
  if (body.caller_assertion) identity.callerAssertion = body.caller_assertion;
  return { identity, service: body.service === true };
}

// RFC 9728 §3: the metadata document that tells an MCP client which
// Authorization Server to use. Served publicly and unauthenticated — that is the
// point: it is how an unauthenticated client discovers where to get a token.
// It contains no secret, only URLs.
export function protectedResourceMetadata(env: Env): Response {
  // Fail closed on a mis-templated deploy, like every other path in this file.
  // Serving the document with these unset yields {"authorization_servers":
  // [null]} and no `resource` at all (JSON.stringify drops undefined) — and
  // because the success response is `public, max-age=3600`, clients and
  // intermediaries would keep that garbage for an hour after the config is
  // corrected. 500 + no-store instead: loud, and never cached.
  if (!env.OAUTH_RS_RESOURCE || !env.MCP_AUTH_SERVER) {
    console.error("gateway: protected-resource metadata requested without OAUTH_RS_RESOURCE/MCP_AUTH_SERVER — refusing");
    return new Response("misconfigured", { status: 500, headers: { "cache-control": "no-store" } });
  }
  return Response.json({
    resource: env.OAUTH_RS_RESOURCE,
    authorization_servers: [env.MCP_AUTH_SERVER],
    // Header only — see bearerToken above.
    bearer_methods_supported: ["header"],
    // Twin of src/index.ts's scopesSupported (the platform AS's own list);
    // gateway/ cannot import from src/, so test/constant-parity.node.test.ts
    // pins the two equal.
    scopes_supported: ["openid", "profile", "email"],
  }, {
    // Public, cacheable metadata; clients re-fetch it on each fresh auth.
    headers: { "cache-control": "public, max-age=3600" },
  });
}

// RFC 9728 §5.1 / MCP auth: a 401 whose WWW-Authenticate names the metadata
// document. Without `resource_metadata` a client has no way to find the AS and
// simply fails, so this header is what makes the whole flow discoverable.
//
// `invalidToken` distinguishes "presented a bad/expired token" from "presented
// none": RFC 6750 §3.1 says only the former carries `error="invalid_token"`,
// and MCP clients use exactly that to choose "silently refresh" over "restart
// authorization" — without it a client can re-present an expired token in a loop.
export function unauthorizedChallenge(env: Env, invalidToken = false): Response {
  // The metadata document lives on the RESOURCE's origin, derived from
  // OAUTH_RS_RESOURCE so the two can never disagree. Advertises the spec-correct
  // path-inserted form (RFC 9728 §3.1).
  let url = "";
  try {
    const resource = new URL(env.OAUTH_RS_RESOURCE ?? "");
    url = `${resource.origin}${protectedResourcePathFor(resource.pathname)}`;
  } catch { url = ""; }
  const params: string[] = [];
  if (invalidToken) {
    params.push('error="invalid_token"');
    params.push('error_description="the access token is invalid or expired"');
  }
  // Without resource_metadata a client cannot discover the AS at all, so a bare
  // `Bearer` is only the mis-templated-deploy fallback.
  if (url) params.push(`resource_metadata="${url}"`);
  return new Response("unauthorized", {
    status: 401,
    headers: {
      "content-type": "text/plain",
      "www-authenticate": params.length ? `Bearer ${params.join(", ")}` : "Bearer",
    },
  });
}
