import { ACCESS_COOKIE, GROUP_PREFIX, type AccessIdentity } from "./access";
import { appFromHostname } from "./red";

// Identity-bearing headers a client must never supply to the container.
// The exact X-Forwarded-* names we own, plus the entire cf-access-* family
// (the gateway has already consumed the Access JWT before this runs, so the
// container never needs any cf-access-* header — and must not trust one).
// x-caller-assertion is stripped on BOTH perimeters (Access and MCP): it is a
// platform-signed credential (Connections v1) that only the gateway may set —
// a client-supplied value must never survive to be re-injected or forwarded.
const STRIP_EXACT = ["x-forwarded-user", "x-forwarded-groups", "x-forwarded-email", "x-caller-assertion"];
const STRIP_PREFIXES = ["cf-access-"];
// Both of Cloudflare Access's session cookies, on the app's own hostname. The
// Access JWT arrives TWICE, as cf-access-jwt-assertion (covered by the prefix
// rule above) and as the CF_Authorization cookie, and index.ts accepts either
// as a credential. The gateway has already consumed the session before this
// runs, so the app needs neither cookie, and leaving either behind (stripping
// only the header once did) hands the app a live bearer for its own perimeter:
// valid until exp (Access session_duration 24h) and re-accepted with no
// session or revocation lookup, so app code could replay any visitor's
// identity for a day, past a revoke_access. The first name is access.ts's
// ACCESS_COOKIE rather than a second literal: index.ts reads the cookie
// through that constant, and a rename there that missed a hand-written copy
// here would leave the live bearer in place with nothing failing.
const STRIP_COOKIES = [ACCESS_COOKIE, "CF_AppSession"];

// In MCP mode the caller's credential is a platform-issued OAuth bearer token in
// `Authorization`. The gateway has already consumed it, and the app must never
// see it: a leaked app-scoped token would let the app impersonate its own user
// against the platform, and R3 says the app performs no authentication anyway.
// Stripped only in MCP mode — on the Access path `Authorization` is not a
// platform credential, and removing it there would be a silent behavior change
// for existing apps.
const STRIP_EXACT_MCP = [...STRIP_EXACT, "authorization"];

// Proxy headers the gateway OWNS (R30). Cloudflare's edge APPENDS the client
// address to whatever X-Forwarded-For the caller sent, and passes
// X-Forwarded-Host, X-Forwarded-Proto and RFC 7239 Forwarded through
// untouched, so each of them reaches the app partly or wholly caller-written.
// An app that builds a link from X-Forwarded-Host, rate limits on the first
// X-Forwarded-For entry, or decides on a Secure cookie from X-Forwarded-Proto
// is reading a value its own visitor chose. Overwrite each with what the
// gateway actually knows, and delete the ones with no authoritative value.
function setProxyAuthority(headers: Headers, req: Request): void {
  const url = new URL(req.url);
  headers.set("X-Forwarded-Host", url.host);
  // Always https: an app hostname is served only over TLS (withHsts stamps
  // every gateway response, including the refusals) and there is no plain
  // http listener to arrive from.
  headers.set("X-Forwarded-Proto", "https");
  // CF-Connecting-IP is written by Cloudflare's edge and cannot be supplied by
  // the client, so it is the one address here that is a fact. Where there is
  // no edge in front (a synthetic Request in a test, a direct service-binding
  // call) there is no authoritative value at all, so the header is REMOVED
  // rather than guessed: an app reading an absent header can fall back, while
  // an app reading a fabricated one cannot tell.
  const clientIp = req.headers.get("cf-connecting-ip");
  if (clientIp) headers.set("X-Forwarded-For", clientIp);
  else headers.delete("X-Forwarded-For");
  // RFC 7239. The gateway does not produce one, so any value present came from
  // the caller and says whatever the caller wanted it to say.
  headers.delete("Forwarded");
}

// Twin of src/naming.ts's groupsVisibleToApp (gateway/ builds separately and
// cannot import src/), parity-pinned by test/constant-parity.node.test.ts.
//
// The ONLY groups an app may be told about (R29). An app's authorization is
// its own members group or its open twin; everything else in a person's
// `inno-` list is information about the rest of the platform, including
// whether they are a platform admin. The Okta claim cannot be narrowed per
// app on this org tier (OPERATIONS section 9(a)), so the Access JWT arrives with
// all of them and this is where the narrowing has to happen. Exact names, not
// a prefix match, and fixed order: members, then open.
export function groupsVisibleToApp(app: string, groups: readonly string[]): string[] {
  return [`${GROUP_PREFIX}${app}-users`, `${GROUP_PREFIX}${app}-open`].filter((g) => groups.includes(g));
}

export function sanitizeAndInject(
  req: Request, identity: AccessIdentity, opts: { mcpMode?: boolean } = {},
): Request {
  const headers = new Headers(req.headers);
  for (const h of opts.mcpMode ? STRIP_EXACT_MCP : STRIP_EXACT) headers.delete(h);
  // Headers.keys() are already lowercased by the Fetch API, so no toLowerCase.
  for (const name of [...headers.keys()]) {
    if (STRIP_PREFIXES.some((p) => name.startsWith(p))) headers.delete(name);
  }
  setProxyAuthority(headers, req);
  // Rebuild Cookie without either Access session cookie, preserving the app's
  // own cookies (an app legitimately sets its own; blanket-deleting would break
  // every session an app keeps). Cookie names are case-sensitive per RFC 6265,
  // so an exact match is right here — unlike the header names above.
  const cookie = headers.get("cookie");
  if (cookie !== null) {
    const kept = cookie.split(";")
      .filter((pair) => !STRIP_COOKIES.includes(pair.trimStart().split("=")[0].trim()));
    if (kept.length === cookie.split(";").length) {
      // untouched — leave the original bytes alone rather than re-serializing
    } else if (kept.some((p) => p.trim() !== "")) {
      headers.set("cookie", kept.join(";").replace(/^[;\s]+/, ""));
    } else {
      headers.delete("cookie");
    }
  }
  headers.set("X-Forwarded-User", identity.email);
  headers.set("X-Forwarded-Email", identity.email);
  // Derived from the URL's hostname rather than a binding, the same derivation
  // index.ts uses for the RED caller bucket: it is populated on every request
  // shape (the Host header is not, on a synthetic Request) and it is the name
  // the request was actually routed to. Doing it INSIDE sanitizeAndInject
  // rather than at the call site means no branch (Access, MCP, dev) can skip
  // it, and the MCP path does not rely on the platform having narrowed.
  const appName = appFromHostname(new URL(req.url).hostname);
  headers.set("X-Forwarded-Groups", groupsVisibleToApp(appName, identity.groups).join(","));
  // Connections v1: only set when introspection actually minted one (MCP path,
  // CALLER_ASSERTION_KEY provisioned). The app echoes this value back to
  // /_connections/{name}; the gateway never trusts one from the client (see
  // STRIP_EXACT above), only one it just verified came from the platform.
  if (identity.callerAssertion) headers.set("X-Caller-Assertion", identity.callerAssertion);
  return new Request(req, { headers });
}
