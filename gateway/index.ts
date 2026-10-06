import { Hono } from "hono";
import { getCookie } from "hono/cookie";
import { Container, getContainer } from "@cloudflare/containers";
import { createRemoteJWKSet } from "jose";
import type { Env } from "./env";
import { verifyAccessJwt, ACCESS_JWT_HEADER, ACCESS_COOKIE, GROUP_PREFIX, type AccessIdentity } from "./access";
import { sanitizeAndInject } from "./identity";
import { errLine } from "./log-text";
import { handleStorage, type StorageEnv } from "./storage";
import {
  authenticateMcp, bearerToken, protectedResourceMetadata, unauthorizedChallenge, isProtectedResourceRequest,
} from "./mcp-auth";
import { mcpWorkRequest, shouldTouch, markTouched, sendTouch } from "./activity";
import { writeRed, pathClass, classifyStatus, appFromHostname, userBucket } from "./red";

// The @cloudflare/containers runtime routes container calls through an internal
// `ContainerProxy` Durable Object that it looks up via `ctx.exports.ContainerProxy`.
// It only lands on `ctx.exports` if the Worker entrypoint re-exports it — without
// this, container startup fails with "ctx.exports.ContainerProxy is undefined".
export { ContainerProxy } from "@cloudflare/containers";

// Scale-to-zero timeout resolution. The platform injects SLEEP_AFTER at
// deploy time (`wrangler deploy --var SLEEP_AFTER:...` in platform-ci,
// sourced from the config store's container.sleep_after — app-overridable);
// the grammar guard mirrors the platform's server-side validation so a
// malformed var can never wedge container startup. That validation and this
// default both live in src/config.ts's container.sleep_after entry; gateway/
// builds separately and cannot import it, so the grammar and the "10m" are
// hand-written twins that test/constant-parity.node.test.ts holds to the
// platform's own. Exported as a function so the guard is EXECUTABLE in tests:
// workerd's native DurableObject base rejects stub state objects, so the
// constructor path itself can't be.
export function resolveSleepAfter(v: string | undefined, fallback = "10m"): string {
  if (v && /^[0-9]{1,4}(s|m|h)$/.test(v)) return v;
  // Say so rather than silently keeping the default: an owner who sets
  // container.sleep_after to something this grammar rejects otherwise sees
  // the config store accept the value while the container keeps sleeping at
  // 10m, with no surface anywhere explaining the discrepancy.
  if (v) console.warn(`gateway: ignoring malformed SLEEP_AFTER ${JSON.stringify(v)} — keeping ${fallback}`);
  return fallback;
}

// Variables delivery: the platform pushes per-app env vars onto THIS gateway
// script as APPVAR_-prefixed Worker secrets (src/variables/sync.ts holds the
// twin constant — gateway/ builds separately and cannot import it;
// constant-parity pins the two). Unpack them into the container's env at
// instance start, stripped of the prefix, so app code reads the literal
// name. Secrets surface on `env` as plain strings exactly like vars; the
// typeof filter keeps bindings (DB/FILES/...) out. Pure function for the
// same workerd reason as resolveSleepAfter above.
const APPVAR_PREFIX = "APPVAR_";
export function collectAppVars(env: Env): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) {
    if (k.startsWith(APPVAR_PREFIX) && typeof v === "string") out[k.slice(APPVAR_PREFIX.length)] = v;
  }
  return out;
}

// NOTE: the lowercased class name is load-bearing OUTSIDE this worker:
// src/naming.ts `containerAppName` derives the billed Cloudflare Container
// application name as `<worker>-appcontainer` from `class AppContainer`.
// Renaming this class silently orphans the billed container on teardown; keep
// the two in sync (see the reciprocal note in src/naming.ts).
export class AppContainer extends Container<Env> {
  defaultPort = 8080;
  sleepAfter = "10m";
  constructor(...args: ConstructorParameters<typeof Container<Env>>) {
    super(...args);
    this.sleepAfter = resolveSleepAfter((args[1] as Env).SLEEP_AFTER, this.sleepAfter);
    this.envVars = collectAppVars(args[1] as Env);
  }
}
// Register the storage.internal outbound handler by ASSIGNING after the class
// so the assignment invokes Container's inherited static `outboundByHost` SETTER
// (which registers the handler in the package's outbound registry). Declaring
// `static outboundByHost = {...}` in the class body instead creates an own data
// property that SHADOWS the setter — the handler is never registered, so the
// container's http://storage.internal calls fall through to the enableInternet
// fallback and fail with HTTP 530 (the live "no D1 writes" bug).
// The cast is the ONE place the container-only invariant is asserted: this
// handler is reachable solely from a running AppContainer, which exists only
// on the container-shaped variants, which are exactly the ones that bind
// DB/FILES (optional on Env because the function-shaped variants don't).
AppContainer.outboundByHost = {
  "storage.internal": (req: Request, env: Env) => handleStorage(req, env as StorageEnv),
};

type Deps = {
  jwks: (env: Env) => ReturnType<typeof createRemoteJWKSet>;
  forwardToContainer: (env: Env, req: Request) => Promise<Response>;
  // Function-shaped apps (env.APP_WORKER bound) forward here instead — a service
  // binding to the app's own Worker. See makeApp's dispatch below.
  forwardToWorker: (env: Env, req: Request) => Promise<Response>;
};

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
export const realDeps: Deps = {
  jwks: (env) => {
    const url = `https://${env.ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`;
    let j = jwksCache.get(url);
    if (!j) { j = createRemoteJWKSet(new URL(url)); jwksCache.set(url, j); }
    return j;
  },
  // env.APP exists only on container-shaped deploys; the `!` is safe because
  // makeApp reaches this branch only when APP_WORKER is absent, and the two
  // are bound by mutually exclusive wrangler variants.
  forwardToContainer: (env, req) => getContainer(env.APP!).fetch(req),
  // env.APP_WORKER exists only on function-shaped deploys, where makeApp dispatches
  // here; the `!` is safe because the container branch is chosen whenever it's absent.
  forwardToWorker: (env, req) => env.APP_WORKER!.fetch(req),
};

// HSTS for app hostnames lives HERE, not at an edge setting: APP-SECURITY
// tells authors transport headers are handled in front of the app, and the
// panel's public/_headers covers only the platform's own hostname. A proxied
// fetch() Response carries immutable headers, so the header is added on a
// rebuilt Response — except upgrade responses (101/WebSocket), which a
// rebuild would strip the socket from.
const HSTS_VALUE = "max-age=31536000";
export function withHsts(res: Response): Response {
  if (res.status === 101 || (res as { webSocket?: unknown }).webSocket) return res;
  const out = new Response(res.body, res);
  out.headers.set("Strict-Transport-Security", HSTS_VALUE);
  return out;
}

// Queue a fire-and-forget activity touch. waitUntil when available; the
// detached promise still runs (and sendTouch never rejects) when not.
function queueTouch(c: { executionCtx: { waitUntil(p: Promise<unknown>): void } }, platform: Fetcher, payload: Record<string, string>): void {
  const send = sendTouch(platform, payload);
  try { c.executionCtx.waitUntil(send); } catch { /* no ExecutionContext (tests) */ }
}

// The caller bucket recorded for a request that never got as far as an
// identity: the gateway's own 401/403 refusals. Those requests MUST still be
// counted — a fleet-wide auth breakage (a stale ACCESS_AUD, an expired
// service token) is exactly the kind of outage that shows up as "every
// request 4xx" and nowhere else.
const ANON_BUCKET = "anon";

export function makeApp(deps: Deps = realDeps) {
  const app = new Hono<{ Bindings: Env; Variables: { redUser?: string; redStatus?: "err" } }>();
  // Every response served on the app hostname carries HSTS — the proxied app
  // response and the gateway's own refusals (401/403/metadata) alike.
  app.use("*", async (c, next) => {
    await next();
    c.res = withHsts(c.res);
  });
  // RED signal (Phase 2). Wraps the whole handler so the gateway's own
  // refusals are measured alongside proxied app responses — a fleet-wide auth
  // breakage is "every request 4xx" and shows up nowhere else. Observation
  // only: nothing here changes a status, a body, or an error.
  //
  // `err` (the app was unreachable) cannot be read off the response, because
  // Hono catches a handler throw and turns it into a 500 BEFORE next()
  // returns — indistinguishable from an app that genuinely answered 500. So
  // the forward marks the class in `redStatus` and this reads the override.
  app.use("*", async (c, next) => {
    const started = Date.now();
    const app_ = appFromHostname(new URL(c.req.url).hostname);
    const path = pathClass(c.req.path);
    const record = (status: Parameters<typeof writeRed>[1]["status"]) => writeRed(c.env, {
      app: app_, path, status,
      user: c.get("redUser") ?? ANON_BUCKET,
      latencyMs: Date.now() - started,
    });
    try {
      await next();
    } catch (e) {
      record("err");
      throw e;
    }
    record(c.get("redStatus") ?? classifyStatus(c.res.status));
  });
  app.all("*", async (c) => {
    const env = c.env;
    const path = c.req.path;
    // The Host header is not guaranteed present on every Request object
    // (notably absent on synthetic requests built with `new Request()`, as
    // opposed to ones that arrived over real HTTP); the URL's own hostname
    // is always populated and always matches what routed here. Derived once
    // for the touch debounce key and RED's caller bucket (identity.ts makes
    // the same derivation for R29's narrowing, inside sanitizeAndInject so
    // no branch can skip it).
    const host = new URL(c.req.url).hostname;
    // The one request shape a credential with NO user identity is good for,
    // on both perimeters: the platform's health probe (an Access SERVICE
    // token on the sso path, the health-probe bearer on the MCP path). Any
    // other path keeps the hard identity requirement: a service credential
    // can never browse the app or reach data as a person.
    const isHealthProbe = c.req.method === "GET" && path === "/healthz";
    let identity: AccessIdentity;
    // MCP mode (mcp-type apps): this gateway is an OAuth Resource Server, not an
    // Access-terminating proxy. Handled before the dev branch so the discovery
    // document and the 401 challenge behave identically in dev and production —
    // an MCP client's very first request depends on both.
    if (env.OAUTH_RS_MODE === "true") {
      // Public, unauthenticated by design: this is how a client with no token
      // discovers which Authorization Server to use. Contains only URLs.
      if (c.req.method === "GET" && isProtectedResourceRequest(env, path)) {
        return protectedResourceMetadata(env);
      }
      const auth = await authenticateMcp(env, c.req.raw, env.OAUTH_RS_RESOURCE ?? "");
      if (!auth) {
        // Distinguish "presented a bad/expired token" (→ error=invalid_token, so
        // the client refreshes) from "presented none" (→ start authorization).
        const hadToken = bearerToken(c.req.raw) !== null;
        console.warn(`gateway: 401 ${hadToken ? "invalid" : "no"} bearer (${c.req.method} ${path})`);
        return unauthorizedChallenge(env, hadToken);
      }
      // Same rule the Access path applies to its service token (isHealthProbe
      // above): a credential with no user identity is good for GET /healthz
      // and nothing else.
      if (auth.service && !isHealthProbe) {
        console.warn(`gateway: 403 service credential outside /healthz (${c.req.method} ${path})`);
        // 403, not the Access path's 401, and deliberately so: the token is
        // VALID, it just isn't authorized for this request, which RFC 6750
        // §3.1 calls insufficient_scope. A 401 would tell the client to
        // re-authenticate, and a service credential re-authenticating gets
        // the same credential back — an infinite loop. The challenge header
        // is what RFC 6750 §3 says a 403 SHOULD carry.
        return c.text("forbidden", 403, {
          "www-authenticate": 'Bearer error="insufficient_scope", error_description="service credential is accepted only for GET /healthz"',
        });
      }
      identity = auth.identity;
      // Human-activity touch (spec 2026-08-18): a work request from a real
      // user advances the idle clock. Debounce-gated BEFORE the body peek so
      // the clone/parse cost is paid at most once per window; protocol
      // chatter, probes, and tokenless noise never qualify.
      if (env.PLATFORM && identity.callerAssertion && c.req.method === "POST" && path === "/mcp") {
        if (shouldTouch(host, Date.now()) && (await mcpWorkRequest(c.req.raw))) {
          markTouched(host, Date.now());
          queueTouch(c, env.PLATFORM, { assertion: identity.callerAssertion });
        }
      }
    } else if (env.ENVIRONMENT === "dev" && env.DEV_MOCK_IDENTITY === "enabled") {
      identity = {
        // A reserved placeholder (RFC 2606's .invalid), never a deliverable
        // address: whatever this branch synthesizes is echoed to the app and
        // can end up in its logs as though a real person had signed in.
        email: c.req.header("X-Mock-User") ?? "dev@example.invalid",
        // Same inno- filter production applies (access.ts), so dev can't inject
        // a non-inno group the real path would strip.
        groups: (c.req.header("X-Mock-Groups") ?? "").split(",").map((s) => s.trim()).filter((g) => g.startsWith(GROUP_PREFIX)),
      };
    } else {
      // Fail CLOSED on a mis-templated deploy: without an AUD and team domain
      // there is nothing to verify a JWT against, and proceeding would check the
      // token against `undefined` rather than this app's Access application.
      if (!env.ACCESS_AUD || !env.ACCESS_TEAM_DOMAIN) {
        console.error("gateway: Access mode without ACCESS_AUD/ACCESS_TEAM_DOMAIN — refusing all requests");
        return c.text("unauthorized", 401);
      }
      // hono's own cookie reader rather than a hand-rolled split: the header
      // is already parsed for this request, and a name that is a prefix of
      // another cookie's name cannot match by accident.
      const token = c.req.header(ACCESS_JWT_HEADER) ?? getCookie(c, ACCESS_COOKIE);
      if (!token) { console.warn(`gateway: 401 no Access token (${c.req.method} ${path})`); return c.text("unauthorized", 401); }
      // The platform's health probe authenticates with an Access SERVICE
      // token, a valid JWT with no user identity, accepted for exactly the
      // one request shape isHealthProbe (above) names.
      try {
        identity = await verifyAccessJwt(token,
          { jwks: deps.jwks(env), aud: env.ACCESS_AUD, teamDomain: env.ACCESS_TEAM_DOMAIN },
          { allowService: isHealthProbe });
      } catch (e) {
        console.warn(`gateway: 401 ${errLine(e, 120)} (${c.req.method} ${path})`);
        return c.text("unauthorized", 401);
      }
      // Human-activity touch (spec 2026-08-18): any Access-verified request
      // with a real user identity is human use — the service token's empty
      // email excludes probes by construction. The platform re-verifies the
      // forwarded JWT against this app's stored AUD before stamping.
      if (env.PLATFORM && identity.email) {
        if (shouldTouch(host, Date.now())) {
          markTouched(host, Date.now());
          queueTouch(c, env.PLATFORM, { host, jwt: token });
        }
      }
    }
    // NOTE: this handler proxies ALL paths (including /_storage/*) to the
    // container via forwardToContainer. handleStorage is never called here —
    // it is wired only as AppContainer's outboundByHost["storage.internal"]
    // handler above, reachable solely by the app's own container in-runtime.
    // Do not add a /_storage route here: that would let the public internet
    // reach handleStorage's arbitrary SQL/R2 access directly.
    // RED's caller bucket, now that there IS a verified identity. Set before
    // the forward so the surrounding middleware reads it whichever way the
    // request ends (proxied response, or a throw from the app).
    c.set("redUser", await userBucket(appFromHostname(host), identity.email || "service"));

    const proxied = sanitizeAndInject(c.req.raw, identity, { mcpMode: env.OAUTH_RS_MODE === "true" });
    // Deployment-type dispatch: function-shaped apps carry an APP_WORKER service
    // binding and forward to the app's own Worker; container-type apps (no such
    // binding) forward to the container. Either way the gateway did the Access
    // verification and identity injection FIRST, so the target only ever sees a
    // sanitized, authenticated request with spoof-proof X-Forwarded-* headers.
    // AWAITED inside the try (not returned as a promise) so a forward that
    // rejects is caught HERE and can be recorded as RED's `err` class — the
    // "app unreachable" signal a 5xx-only classifier misses. The error is
    // re-thrown unchanged; the caller sees exactly what it saw before.
    try {
      if (env.APP_WORKER) return await deps.forwardToWorker(env, proxied);
      return await deps.forwardToContainer(env, proxied);
    } catch (e) {
      c.set("redStatus", "err");
      throw e;
    }
  });
  return app;
}

export default makeApp();
