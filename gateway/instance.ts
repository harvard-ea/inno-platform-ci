// The gateway's two instance names, read from its own config vars:
// HOST_PREFIX is what it strips from its hostname to find its app, and
// GROUP_PREFIX is what every group it carries starts with. Both are rendered
// into every gateway config from the instance manifest (naming.hostPrefix,
// naming.groupPrefix), so they sit beside the code that reads them and come
// from the same gateway.ref; another instance's mirror needs no code change.
//
// The twin of src/instance.ts's prefix reads (gateway/ builds separately and
// imports nothing from src/). test/instance-formula-parity.node.test.ts holds
// the rule below to the Worker's and to tenant CI's, verdict for verdict,
// and every formula built from these two to its src/naming.ts builder.
import type { Env } from "./env";

export type Prefixes = Readonly<{ hostPrefix: string; groupPrefix: string }>;

// The manifest's prefix rule (scripts/lib/manifest.mjs `prefix`): the app
// name alphabet, ending in "-" so a name appended to it stays readable. The
// host prefix alone may be empty (apps at <app>.<domain>); the group prefix
// never is. Only checked here, never repaired: a config that breaks it did
// not come from a render.
const PREFIX_RE = /^[a-z0-9][a-z0-9-]*-$/;
const HOST_PREFIX_RE = /^(?:[a-z0-9][a-z0-9-]*-)?$/;

/**
 * The two prefixes, or the reason this config cannot give them. Never a
 * default: a gateway that guessed would strip the wrong prefix and forward
 * the wrong groups while looking healthy, so index.ts refuses every request
 * instead (500, one log line naming the var).
 */
export function readPrefixes(env: Pick<Env, "HOST_PREFIX" | "GROUP_PREFIX">):
  { ok: true; prefixes: Prefixes } | { ok: false; error: string } {
  for (const name of ["HOST_PREFIX", "GROUP_PREFIX"] as const) {
    const v: unknown = env[name];
    if (typeof v !== "string" || !(name === "HOST_PREFIX" ? HOST_PREFIX_RE : PREFIX_RE).test(v)) {
      const seen = v === undefined ? "is missing" : `is ${JSON.stringify(String(v).slice(0, 40))}, not a name prefix (a-z, 0-9 and "-", ending in "-")`;
      return { ok: false, error: `${name} ${seen}; it is rendered into this gateway's config from the instance manifest` };
    }
  }
  return { ok: true, prefixes: { hostPrefix: env.HOST_PREFIX!, groupPrefix: env.GROUP_PREFIX! } };
}

/**
 * The groups of `raw` that are this instance's: the one filter the Access
 * path (access.ts), the MCP path (mcp-auth.ts) and the dev mock path
 * (index.ts) all apply, so the three producers of an identity cannot
 * disagree about what an app may be told. A non-string entry is dropped.
 * Refuses an empty prefix, which would keep every group.
 */
export function instanceGroups(groupPrefix: string, raw: unknown): string[] {
  if (!groupPrefix) throw new Error("instanceGroups: no group prefix");
  return (Array.isArray(raw) ? raw : []).filter((g): g is string => typeof g === "string" && g.startsWith(groupPrefix));
}
