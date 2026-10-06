import type { AppContainer } from "./index";

export type Env = {
  // Container-shaped deploys only (gateway/wrangler.jsonc and
  // wrangler.mcp-container.jsonc). The function-shaped variants declare no
  // D1/R2/container at all — storage belongs to the app Worker there — so
  // these are OPTIONAL like every other per-variant binding below. Nothing
  // reads them outside the container path: handleStorage is reachable only as
  // AppContainer's storage.internal outbound handler, and the request
  // dispatch checks APP_WORKER first (see index.ts).
  DB?: D1Database; FILES?: R2Bucket; APP?: DurableObjectNamespace<AppContainer>;
  // Cloudflare Access config, templated per app. OPTIONAL because mcp-type apps
  // have no Access application at all (see the MCP block below) — the Access
  // branch in index.ts refuses to run without them rather than verifying a JWT
  // against `undefined`.
  ACCESS_AUD?: string; ACCESS_TEAM_DOMAIN?: string;
  ENVIRONMENT: string;
  // The dev mock-identity switch (R37): index.ts's X-Mock-User branch requires
  // it to equal "enabled". NOTHING SUPPLIES IT TODAY, in any runtime. The
  // gateway configs name it inside their `dev` block, but `vars` is not a field
  // wrangler accepts there (wrangler 4.x warns "Unexpected fields found in dev
  // field" and discards the block), so the value reaches neither `wrangler dev`
  // nor a deploy, and the mock-identity branch is unreachable as configured.
  // This stays declared as the belt: a gitignored `.dev.vars` file is the
  // supported way to supply a local-only var (OPERATIONS §4.5), and even then a
  // DEPLOY still cannot carry it, because ci/template-wrangler.mjs refuses to
  // template any gateway config whose deployed vars name it.
  DEV_MOCK_IDENTITY?: string;
  // Injected at deploy time by platform-ci (config store: container.sleep_after).
  SLEEP_AFTER?: string;
  // Present ONLY on function-shaped apps: a service binding to the app's own Worker
  // (the "Worker behind the same gateway" deployment type). When set, the
  // gateway forwards authenticated requests here instead of to the container —
  // the app Worker is not publicly routable, so the gateway stays the only
  // entrypoint and identity boundary. Container-type apps never bind this.
  APP_WORKER?: Fetcher;
  // --- mcp-type apps only (gateway/wrangler.mcp.jsonc) ---------------------
  // Present ONLY on mcp-type deploys, where the gateway is an OAuth Resource
  // Server instead of an Access-terminating proxy. OAUTH_RS_MODE is the switch;
  // ACCESS_AUD is absent on these apps because they have no Access application.
  OAUTH_RS_MODE?: string;
  // This app's RFC 8707/9728 resource identifier — `https://inno-{app}.{domain}/mcp`,
  // templated by CI from the deploy broker's `oauth_rs_resource`. Compared by EXACT
  // match against a token's audience, so it must not be rebuilt ad hoc.
  OAUTH_RS_RESOURCE?: string;
  // The Authorization Server issuer the protected-resource metadata advertises
  // (the platform's own origin). Keeps its MCP_ prefix: this names the
  // MCP-protocol Authorization Server per RFC 9728, protocol vocabulary rather
  // than the retired type vocabulary, so it is exempt from the Phase B rename
  // (spec Decision 4 keep-list).
  MCP_AUTH_SERVER?: string;
  // Shared secret proving to /app-introspect that this caller is a GATEWAY, not
  // some holder of an app access token. Only a caller presenting it receives a
  // caller_assertion — the credential that opens /_connections/fetch. Pushed as
  // a Worker secret by the platform at deploy time, never templated into the
  // config (the app's CI can read its own config, and must not read this).
  // The platform requires this header once its own key is provisioned, unless
  // its admin switch (connections.gateway_key_required) is explicitly false.
  // A gateway deployed before the key existed has none to send and must be
  // redeployed to receive it.
  // Connections is not all a keyless gateway loses: the oauth-rs idle-clock
  // touch (index.ts) fires only when the identity carries a caller assertion,
  // which is exactly what the platform withholds here, so an MCP app in real
  // use stops advancing its clock and the lifecycle engine warns and then
  // stops it. One redeploy restores both.
  GATEWAY_INTROSPECT_KEY?: string;
  // RED signal (NoOp Phase 2, gateway/red.ts). Bound on all four gateway
  // variants, and OPTIONAL for a reason that is load-bearing rather than
  // stylistic: an app whose gateway build predates the binding writes nothing
  // and reads `unknown` (never zero) until its next deploy. The absence IS the
  // rollout gate, so nothing here may assume the binding exists.
  RED?: AnalyticsEngineDataset;
  // Service binding to the platform Worker. On oauth-rs variants it carries
  // token introspection; on ALL variants (as of spec 2026-08-18) it carries
  // the human-activity touch. The binding is ROUTING, not authentication —
  // both platform routes are publicly reachable and authenticate by payload;
  // see src/routes/mcp-introspect.ts and src/routes/activity.ts.
  PLATFORM?: Fetcher;
  // Per-link generation secrets, one per deployed data link, templated by CI as
  // LINK_GEN_<SOURCE_APP_UPPER> (ci/template-wrangler.mjs). Cannot appear in
  // this static type because the names derive from source app names — read
  // dynamically in storage.ts, exactly like the LINKED_* D1 bindings they
  // accompany. Absent on a gateway deployed before R09: that app keeps the old
  // "the binding IS the authorization" behavior until its next deploy.
};
