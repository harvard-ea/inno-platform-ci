// RED signal (NoOp spec Phase 2): one Analytics Engine data point per request
// the gateway serves. Requests/Errors/Duration at per-request resolution, which
// is what the daily binary health probe cannot give — an app that 500s for half
// its users all afternoon reads `healthy` on the probe and reads broken here.
//
// Why AE and not D1: `writeDataPoint` is near-free and fire-and-forget, there
// is no write amplification on the app's own database, retention is ~90 days,
// and the SQL API is queryable from the platform's cron (src/lifecycle/red.ts
// is the reader).
//
// CARDINALITY DISCIPLINE. AE indexes are limited, so the app name is the ONLY
// index; everything else is a blob or a double. The user bucket is truncated
// (see userBucket) for the same reason it is blurred: low cardinality and no
// per-caller identifier, in one decision.
//
// The binding is OPTIONAL, and that is the rollout gate: an app whose gateway
// predates this feature simply has no RED binding, writes nothing, and reads
// `unknown` (never zero) on every consuming surface until its next deploy —
// the same adoption story as observability.enabled (2026-07-23) and Workers
// Logs (§7.10).
import { GROUP_PREFIX } from "./access";
import { errLine, hex } from "./log-text";

export type RedEnv = { RED?: AnalyticsEngineDataset };

// The classes the app's OWN error rate is computed from vs. the ones that must
// never contaminate it:
//   app         — real user traffic through the front door
//   healthz     — the platform's own synthetic probe (excluded from app rate)
//   connections — the connection broker's backend fetch, written PLATFORM-side
//                 (src/routes/connections.ts): a dead or locked backend
//                 credential is its own failure class, not the app's 500s.
// `storage-proxy` from the spec is deliberately absent: that traffic runs
// container→storage.internal through an outbound handler that never sees the
// app name, and it needs no label to be excluded from the app's rate because
// it never crosses this boundary at all.
export type PathClass = "app" | "healthz" | "connections";

export function pathClass(pathname: string): PathClass {
  return pathname === "/healthz" ? "healthz" : "app";
}

// Status CLASS, not status code: a 3-character bucket keeps blob cardinality at
// five values instead of dozens. `err` is its own class and load-bearing — a
// container refusing connections makes the proxied fetch THROW rather than
// return a 5xx, and "the app is unreachable" is precisely the signal a
// 5xx-only classifier would miss.
export type StatusClass = "2xx" | "3xx" | "4xx" | "5xx" | "err";

export function classifyStatus(status: number): StatusClass {
  if (status >= 500) return "5xx";
  if (status >= 400) return "4xx";
  if (status >= 300) return "3xx";
  return "2xx";
}

export function isError(cls: StatusClass): boolean {
  return cls === "5xx" || cls === "err";
}

// The app name, derived from the request hostname rather than a templated var:
// apps are served at `inno-{app}.{domain}` (src/naming.ts appHostname), so the
// inverse is a prefix strip on the first label. Deriving beats injecting — an
// APP_NAME var would need a new REPLACE marker in all four gateway variants,
// and template-wrangler.mjs asserts exact marker counts, so the marker and the
// mirror's templater would have to land in lockstep or every app's deploy
// breaks. Restated here rather than imported from src/naming.ts for the same
// reason APPVAR_PREFIX and APP_NAME_RE are: the gateway builds separately.
//
// NOT only a metrics helper: identity.ts's sanitizeAndInject also uses it to
// pick which groups an app may see (R29). Reshaping this for RED cardinality
// (truncating a long name, folding rare names into one bucket) would silently
// strip a correctly routed app's groups from X-Forwarded-Groups. Any change
// must still return the exact app name the request was routed to.
//
// The prefix is access.ts's GROUP_PREFIX rather than a second `inno-` literal
// in this build: src/naming.ts collapses the same two uses onto one constant
// (`OKTA_GROUP_PREFIX = INNO_PREFIX`), and the literal is pinned to the
// platform's by test/constant-parity.node.test.ts, so importing it puts this
// derivation behind that pin too.
//
// The twin is NOT total: src/naming.ts's appNameFromHostname returns null for
// a hostname that is not `inno-<name>.<domain>`, while this one always returns
// a name (the bare first label) because every caller here is already handling
// a request the platform routed. The parity pin therefore covers platform
// hosts only, and the non-platform answers differ on purpose.
export function appFromHostname(hostname: string): string {
  const label = hostname.split(".")[0] ?? "";
  return label.startsWith(GROUP_PREFIX) ? label.slice(GROUP_PREFIX.length) : label;
}

// A low-cardinality, deliberately lossy caller bucket. It exists for ONE
// question — "is one user retrying, or are all users failing?" — and 8 hex
// characters answer it while blurring the datum: many callers share a bucket,
// nothing here is reversible to an address, and it is never joined against
// anything. Salted with the app name so the same person is a different bucket
// in every app (no cross-app correlation).
export async function userBucket(app: string, email: string): Promise<string> {
  const data = new TextEncoder().encode(`${app}\0${email}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return hex(new Uint8Array(digest).slice(0, 4));
}

export interface RedPoint {
  app: string;
  path: PathClass;
  status: StatusClass;
  user: string;
  latencyMs: number;
}

// Fire-and-forget, and NEVER throws: telemetry that can fail a user's request
// is worse than no telemetry. A missing binding is the ordinary pre-adoption
// state, not an error worth logging on every request.
export function writeRed(env: RedEnv, p: RedPoint): void {
  if (!env.RED) return;
  try {
    env.RED.writeDataPoint({
      indexes: [p.app],
      blobs: [p.path, p.status, p.user],
      doubles: [p.latencyMs, isError(p.status) ? 1 : 0],
    });
  } catch (e) {
    console.warn(`gateway: RED write failed (continuing): ${errLine(e, 120)}`);
  }
}
