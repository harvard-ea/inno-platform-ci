#!/usr/bin/env node
// Templates the platform's injected wrangler configs (gateway/wrangler*.jsonc
// and gateway/app-worker.jsonc): substitutes the known placeholder markers
// (worker name, D1 database name/id, R2 bucket name, the identity value:
// Access AUD or OAuth RS resource) with the app's real deploy-time values,
// just before `wrangler deploy` runs. The input is always one of those
// templates: no app repo may carry a wrangler config of its own
// (ci/check-config.mjs check 1b), and the platform no longer generates
// inno-{app} repos.
//
// This is a config-mutating script for a security-sensitive file, so it is
// deliberately conservative:
//   - It never does a blind global replace of the bare word "replace"/
//     "REPLACE" — every substitution targets a specific, known marker VALUE
//     (or key+value pair), matched as a whole literal.
//   - It asserts, both before AND after substitution, that each known marker
//     literal is (before) / is no longer (after) present. The post-condition
//     is deliberately scoped to the exact marker literals — not a blanket
//     "replace" word-search — so it can never false-positive on an app name
//     that happens to contain the substring "replace" (e.g. app "toreplace"
//     is a valid slug, and "inno-app-toreplace" legitimately contains
//     "replace"). If a real marker survives, we fail loud rather than ever
//     deploy a half-templated config.
//   - It never REWRITES ENVIRONMENT or any other field. It does ASSERT that a
//     gateway config's deployed vars say ENVIRONMENT "production" and do not
//     carry DEV_MOCK_IDENTITY, which is a refusal, not a substitution (R37).
//
// Usage, one invocation per injected config (platform-ci.yml picks by preset;
// the container gateway is the positional, flagless form):
//   node ci/template-wrangler.mjs <app> <databaseId> <accessAud> [path]                  wrangler.jsonc
//   node ci/template-wrangler.mjs --mcp-container-gateway <app> <databaseId> <resource> [path]  wrangler.mcp-container.jsonc
//   node ci/template-wrangler.mjs --worker-gateway <app> <accessAud> [path]              wrangler.worker.jsonc
//   node ci/template-wrangler.mjs --mcp-gateway <app> <mcpResource> [path]               wrangler.mcp.jsonc
//   node ci/template-wrangler.mjs --worker-app <app> <databaseId> [path]                 app-worker.jsonc
// [path] defaults to wrangler.jsonc. Container-shaped deploys also read
// INNO_IMAGE from the environment. INNO_LINKED_DATABASES is read by those AND
// by --worker-app, the function-shaped half that holds the linked bindings;
// the two gateway modes ignore it (see the CLI block).

import { readFileSync, writeFileSync } from "node:fs";
import { stripJsonComments } from "./check-config.mjs";
import { isMainModule } from "./cli.mjs";

const APP_NAME_RE = /^[a-z][a-z0-9-]{2,28}$/;

// Names that collide with the template markers themselves (an app literally
// named "replace" would make "inno-app-replace" a real value, not a marker,
// and templating would then throw "markers remain" forever). Kept in sync
// with src/registry.ts's RESERVED — a test asserts the two lists are equal —
// but enforced here independently because this script does not consult the
// registry. Exported for that parity test.
export const RESERVED_APP_NAMES = ["platform", "template", "app", "replace", "inno-platform"];

// A double-quote, backslash, or control character in a value interpolated raw
// into the JSONC string could break out of the JSON string literal. `$` is
// rejected too: these values are interpolated into String.replace REPLACEMENT
// strings, where `$1`/`$&`/`$$` are special — real values (hex AUD, UUID db id)
// never contain `$`, so rejecting it closes that footgun for every templater.
const UNSAFE_VALUE_RE = /[$"\\\x00-\x1f]/;

function countMatches(text, re) {
  const m = text.match(re);
  return m ? m.length : 0;
}

// A linked binding name is derived by the platform (src/links.ts linkBindingFor)
// from an app name, so it is always LINKED_ + upper-snake. Re-assert the shape
// here rather than trusting the payload: this value is interpolated into the
// deployed config, and the mandatory LINKED_ prefix is what keeps a link off
// the app's own bindings (DATA, FILES, DB, APP, APP_WORKER, PLATFORM): no
// string that matches this can equal any of them, so no separate reserved
// set is needed. Widen the prefix and that guarantee goes with it.
const LINK_BINDING_RE = /^LINKED_[A-Z][A-Z0-9_]*$/;

const LINK_GENERATION_RE = /^[0-9a-f]{32}$/;

/**
 * Parse and validate the linked-database payload the broker emitted
 * (`linked_databases` on the deploy-token response), passed through CI as JSON
 * in INNO_LINKED_DATABASES. Absent/empty is the common case and yields [].
 *
 * Every field is validated with the same rules as any other deploy value —
 * these end up verbatim inside the deployed wrangler config.
 */
export function parseLinkedDatabases(raw) {
  if (raw === undefined || raw === null || raw === "" || raw === "[]") return [];
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("INNO_LINKED_DATABASES is not valid JSON");
  }
  if (!Array.isArray(parsed)) throw new Error("INNO_LINKED_DATABASES must be a JSON array");
  const seen = new Set();
  return parsed.map((entry) => {
    if (!entry || typeof entry !== "object") throw new Error("each linked database must be an object");
    const { binding, database_name: databaseName, database_id: databaseId } = entry;
    if (typeof binding !== "string" || !LINK_BINDING_RE.test(binding)) {
      throw new Error(`invalid linked binding name: ${JSON.stringify(binding)}`);
    }
    if (seen.has(binding)) throw new Error(`duplicate linked binding: ${binding}`);
    seen.add(binding);
    assertDeployValue(`linked ${binding} database_name`, databaseName);
    assertDeployValue(`linked ${binding} database_id`, databaseId);
    const generation = entry.generation;
    // A liveness token the gateway presents back to /_links/check (R09), not
    // a capability: the seam also requires the gateway key, which app CI
    // never sees. Absent/null whenever the platform has no
    // GATEWAY_INTROSPECT_KEY provisioned (src/routes/deploy.ts's
    // resolveLinkedDatabases, R09 fix round I-1) — the common case on a
    // keyless platform. That is not an error: appendLinkGenerationVars below
    // simply bakes no LINK_GEN_<SOURCE> var for this entry, leaving the
    // gateway in its pre-R09 state for this link. When present, it is
    // validated to the exact shape src/links.ts mints, because it is
    // interpolated verbatim into the deployed config's vars.
    if (generation !== undefined && generation !== null) {
      if (typeof generation !== "string" || !LINK_GENERATION_RE.test(generation)) {
        throw new Error(`invalid linked generation for ${binding}`);
      }
    }
    return { binding, databaseName, databaseId, generation: generation ?? null };
  });
}

/**
 * Append linked D1 bindings to an existing `d1_databases` array, textually, so
 * the template's comments survive (the rest of this script is deliberately
 * textual for the same reason). The array in every platform template is a
 * single-line literal containing no `]`, which is what makes this safe; the
 * exactly-one assertion below fails loud if that ever stops being true.
 */
function appendLinkedDatabases(text, links, label) {
  if (links.length === 0) return text;
  const arrayRe = /("d1_databases"\s*:\s*\[)([^\]]*)(\])/g;
  const count = countMatches(text, arrayRe);
  if (count !== 1) {
    throw new Error(`expected exactly 1 "d1_databases" array in the ${label}, found ${count}`);
  }
  const entries = links
    .map((l) => `{ "binding": "${l.binding}", "database_name": "${l.databaseName}", "database_id": "${l.databaseId}" }`)
    .join(", ");
  return text.replace(/("d1_databases"\s*:\s*\[)([^\]]*)(\])/, (_m, open, body, close) => {
    const trimmed = body.trim();
    return `${open}${trimmed ? `${body.replace(/\s*$/, "")}, ` : ""}${entries}${close}`;
  });
}

// Bake LINK_GEN_<SOURCE> for each linked database into the config's TOP-LEVEL
// `vars` object. Container gateways only: a function-shaped consumer holds its
// linked D1 binding on the app Worker and talks to D1 directly, so there is no
// gateway proxy to gate (R09).
//
// An entry with no generation (null/absent — no GATEWAY_INTROSPECT_KEY
// provisioned platform-wide, R09 fix round I-1) is skipped rather than baked
// as the literal string "null": appendLinkedDatabases above still appends its
// D1 binding, so the link keeps working, just without the liveness gate —
// the same state every container data link was in before R09 shipped.
//
// Anchored at line start, which is what "top-level" means textually in these
// templates: a `"vars"` that opens its own line, never one nested inside
// another object on the same line (a `"dev": { "vars": ... }` block used to be
// exactly that, in two of the four variants, until it was deleted as inert).
// The top-level object in every template contains no `}` of its own, which is
// what makes the textual splice safe; the exactly-one assertion fails loud if
// either of those stops being true.
const TOP_LEVEL_VARS_RE = /^([ \t]*"vars"\s*:\s*\{)([^}]*)(\})/m;

function appendLinkGenerationVars(text, links, label) {
  const withGeneration = links.filter((l) => l.generation != null);
  if (withGeneration.length === 0) return text;
  const count = countMatches(text, new RegExp(TOP_LEVEL_VARS_RE.source, "gm"));
  if (count !== 1) {
    throw new Error(`expected exactly 1 top-level "vars" object in the ${label}, found ${count}`);
  }
  const entries = withGeneration
    .map((l) => `"LINK_GEN_${l.binding.slice("LINKED_".length)}": "${l.generation}"`)
    .join(", ");
  return text.replace(TOP_LEVEL_VARS_RE, (_m, open, body, close) =>
    `${open}${body.trim() ? `${body.replace(/\s*$/, "")}, ` : " "}${entries}${close}`);
}

/**
 * Substitute the wrangler.jsonc template markers with real deploy-time values.
 *
 * Markers substituted (each targeted precisely as a whole literal — never a
 * blind "replace" -> value string replace):
 *   - "inno-app-replace"   (worker name)      -> "inno-app-{app}"
 *   - "inno-replace-db"    (D1 database_name) -> "inno-{app}-db"
 *   - "inno-replace-data"  (R2 bucket_name)   -> "inno-{app}-data"
 *   - `"database_id": "REPLACE"`               -> `"database_id": "{databaseId}"`
 *   - `"ACCESS_AUD": "REPLACE"`                 -> `"ACCESS_AUD": "{accessAud}"`
 *
 * Linked cross-app databases (migration 0028), if any, are appended to
 * `d1_databases` after substitution — for a container app the gateway holds
 * those bindings and serves them over /_storage/linked/{app}/sql/*.
 *
 * @param {string} wranglerText
 * @param {{app: string, databaseId: string, accessAud: string, image?: string, linkedDatabases?: {binding: string, databaseName: string, databaseId: string, generation: string | null}[]}} params
 * @returns {string} the substituted JSONC text
 */
export function templateWrangler(wranglerText, { app, databaseId, accessAud, image, linkedDatabases = [] } = {}) {
  // Shared validation so the container path and the worker templaters enforce
  // identical app-name and deploy-value rules (jq missing-field literals,
  // unsafe characters). See assertAppName/assertDeployValue below.
  assertAppName(app);
  assertDeployValue("databaseId", databaseId);
  assertDeployValue("accessAud", accessAud);
  const imageValue = containerImageValue({ image });

  // Safety net: the template must have exactly two bare `"REPLACE"` literal
  // occurrences (database_id and ACCESS_AUD both start out as "REPLACE").
  // If that count is off, the template shape has changed in a way this
  // script doesn't understand — fail loud rather than guess which
  // occurrence maps to which field.
  const replaceLiteralCount = countMatches(wranglerText, /"REPLACE"/g);
  if (replaceLiteralCount !== 2) {
    throw new Error(
      `expected exactly 2 "REPLACE" markers (database_id, ACCESS_AUD) in wrangler.jsonc, found ${replaceLiteralCount}`,
    );
  }

  // Each marker is matched as a whole literal (name/db/bucket) or a
  // key-scoped literal (database_id / ACCESS_AUD, so the two otherwise-
  // identical "REPLACE" values each map to their own real value instead of
  // both receiving the same substitution). None of these patterns can ever
  // match unrelated text such as a comment, because each requires the full
  // quoted marker string (or key+value pair), not the bare word "replace".
  // Case-sensitive, like every other templater's markers: the input is
  // always one of the platform's own lowercase templates, and the count
  // assertions above already refuse a reshaped file, so an uppercase
  // tolerance here would be a policy the other four paths do not share.
  const markers = [
    { pattern: /"inno-app-replace"/, replacement: `"inno-app-${app}"` },
    { pattern: /"inno-replace-db"/, replacement: `"inno-${app}-db"` },
    { pattern: /"inno-replace-data"/, replacement: `"inno-${app}-data"` },
    { pattern: /("database_id"\s*:\s*)"REPLACE"/, replacement: `$1"${databaseId}"` },
    { pattern: /("ACCESS_AUD"\s*:\s*)"REPLACE"/, replacement: `$1"${accessAud}"` },
    { pattern: /("image"\s*:\s*)"\.\/Dockerfile"/, replacement: `$1"${imageValue}"` },
  ];
  const out = applyMarkers(wranglerText, markers);

  // Cross-app data links (migration 0028). For a CONTAINER app the gateway holds
  // the D1 bindings (the container itself reaches storage over
  // http://storage.internal and holds no credential), so a link becomes an extra
  // gateway binding which gateway/storage.ts exposes under
  // /_storage/linked/{app}/sql/*.
  const withLinks = appendLinkedDatabases(out, linkedDatabases, "wrangler.jsonc");
  const withGenerations = appendLinkGenerationVars(withLinks, linkedDatabases, "wrangler.jsonc");

  // Enforce workers_dev: false (perimeter hardening) via the shared helper, so
  // the container and worker paths apply the identical rule. The *.workers.dev
  // URL is NOT behind Cloudflare Access; closing it makes the Access-protected
  // custom hostname the sole ingress. The input is always the platform's own
  // template, which already says false: this stays as the belt against a
  // template edit that drops or changes the key.
  return forceProductionEnvironment(forceWorkersDevFalse(withGenerations, "wrangler.jsonc"), "wrangler.jsonc");
}

// --- Function-shape templating (migration 0022) -----------------------------
// Function-shaped apps deploy TWO configs — the gateway (service binding, no
// container) and the app's own Worker (its storage bindings). Each carries a
// DIFFERENT marker set than the container wrangler, so they get their own
// templaters rather than overloading templateWrangler (whose exactly-2-REPLACE
// contract is load-bearing for the container path). The shared validation and
// workers_dev enforcement live in helpers so all paths agree on the rules.

function assertAppName(app) {
  if (typeof app !== "string" || !APP_NAME_RE.test(app)) {
    throw new Error(`invalid app name: ${JSON.stringify(app)} (must match ${APP_NAME_RE})`);
  }
  if (RESERVED_APP_NAMES.includes(app)) throw new Error(`reserved app name: ${app}`);
}

// Same JQ_MISSING + unsafe-character guards templateWrangler applies to its
// deploy values, factored out so the worker templaters enforce them identically.
function assertDeployValue(label, v) {
  if (typeof v !== "string" || v.length === 0 || v === "null" || v === "undefined") {
    throw new Error(`invalid ${label}: ${JSON.stringify(v)}`);
  }
  if (UNSAFE_VALUE_RE.test(v)) throw new Error(`invalid character in ${label}`);
}

// A Cloudflare container registry reference pinned by digest (R11). The form
// is what wrangler's own parseImageName accepts and resolveImageName passes
// through unchanged: NAME@sha256:<hex>, where NAME is already scoped to this
// account. A tag alone is deliberately not accepted here — the whole point of
// this reference is that it names one exact image.
const IMAGE_DIGEST_RE = /^registry\.cloudflare\.com\/[0-9a-f]{32}\/[a-z0-9][a-z0-9._-]*@sha256:[0-9a-f]{64}$/;

function assertImageReference(v) {
  assertDeployValue("image", v);
  if (!IMAGE_DIGEST_RE.test(v)) throw new Error(`image must be a digest-pinned Cloudflare registry reference, got ${JSON.stringify(v)}`);
}

// A digest-pinned registry reference is the ONLY value this accepts (I-4 fix
// round). Before this, an empty `image` fell back to a Dockerfile path and
// wrangler rebuilt it at deploy time — with CLOUDFLARE_API_TOKEN already in
// the environment, producing a second image the safety gates never saw, and
// silently reopening on any future edit that let the push step be skipped,
// reordered, or given `continue-on-error`. That fallback is gone entirely: a
// container deploy with no verified, pushed image reference is refused
// outright, never silently downgraded to a rebuild. (No caller outside this
// script's own tests still needs the old Dockerfile path — grepped for one
// during the I-4 fix round and found none.)
function containerImageValue({ image }) {
  if (!image) {
    throw new Error(
      "container deploys must reference the pushed image digest; a Dockerfile build in the deploy job is no longer allowed",
    );
  }
  assertImageReference(image);
  return image;
}

// Per-marker present -> replace -> absent, for all five templaters: every
// marker must be found before substitution and gone after. The post-condition
// is the last line of defense: if a real marker literal survives (say because
// a replacement string coincidentally re-formed one), a half-templated config
// must never deploy.
function applyMarkers(text, markers) {
  let out = text;
  for (const { pattern, replacement } of markers) {
    if (!pattern.test(out)) throw new Error(`template marker not found (unexpected template shape): ${pattern}`);
    out = out.replace(pattern, replacement);
  }
  const remaining = markers.filter((m) => m.pattern.test(out));
  if (remaining.length > 0) {
    throw new Error(`template markers remain after substitution: ${remaining.map((m) => m.pattern).join(", ")}`);
  }
  return out;
}

// workers_dev:false enforced from the comment-stripped PARSE (what wrangler
// reads), never raw text — identical reasoning to templateWrangler's block.
// Force `workers_dev: false` on a templated wrangler config. Shared by the
// container path (templateWrangler) and the worker templaters so all deploy
// types close the *.workers.dev ingress identically.
//
// Decide from the comment-stripped PARSE — exactly what `wrangler deploy` reads
// — never from raw text. A raw-text regex/replace can be fooled by a comment
// that hosts a stray `{` (the injected key lands inside the comment) or that
// merely mentions the key (injection skipped): wrangler then strips comments
// and deploys with the ingress silently left open. A compliant config
// (workers_dev already false) passes through untouched, comments intact; only
// the corrective branch rewrites to comment-free JSON.
function forceWorkersDevFalse(out, label) {
  let config;
  try { config = JSON.parse(stripJsonComments(out)); }
  catch (e) { throw new Error(`templated ${label} is not valid JSON: ${e.message}`); }
  if (config.workers_dev !== false) {
    config.workers_dev = false;
    out = JSON.stringify(config, null, 2) + "\n";
  }
  if (JSON.parse(stripJsonComments(out)).workers_dev !== false) {
    throw new Error(`workers_dev must be exactly \`false\` after templating ${label}`);
  }
  return out;
}

// Every deployed gateway runs in production mode, and nothing but this says so
// (R37). gateway/index.ts carries a dev branch that synthesizes an identity
// from an X-Mock-User request header; it is gated on DEV_MOCK_IDENTITY, which
// nothing supplies in any runtime today (the gateway configs name it inside a
// `dev` block, and wrangler discards a `vars` key there), and this is the
// second lock: a config whose DEPLOYED vars say anything but production, or
// that names the mock-identity var at all, is refused rather than templated.
//
// Decided from the comment-stripped PARSE, exactly what `wrangler deploy`
// reads, for the same reason forceWorkersDevFalse is: a raw-text check can be
// fooled by a comment that merely mentions the key.
//
// This REFUSES rather than corrects. Both guards see only the platform's own
// templates (no app repo may carry a wrangler config, check-config 1b).
// forceWorkersDevFalse corrects because a dropped or flipped key has exactly
// one right value; a gateway config saying "dev", or naming the mock var,
// is a config that did not come from where it should have, and quietly
// rewriting it would hide that.
function forceProductionEnvironment(out, label) {
  let config;
  try { config = JSON.parse(stripJsonComments(out)); }
  catch (e) { throw new Error(`templated ${label} is not valid JSON: ${e.message}`); }
  const vars = config.vars ?? {};
  if (vars.ENVIRONMENT !== "production") {
    throw new Error(`${label}: ENVIRONMENT must be "production" in a deployed gateway, got ${JSON.stringify(vars.ENVIRONMENT)}`);
  }
  if (vars.DEV_MOCK_IDENTITY !== undefined) {
    throw new Error(`${label}: DEV_MOCK_IDENTITY must not appear in a deployed gateway's vars at all. It is a local-development switch, and a config that deploys must never carry it. To set it for local work, use a gitignored .dev.vars file (OPERATIONS §4.5); do not move it into these vars and do not remove this check.`);
  }
  return out;
}

/**
 * Template the function-shape GATEWAY config (gateway/wrangler.worker.jsonc).
 * Markers: the service target ("inno-app-replace-app", substituted BEFORE the
 * name so the name marker can't match inside it), the worker name
 * ("inno-app-replace"), and ACCESS_AUD ("REPLACE"). Exactly one "REPLACE".
 */
export function templateWorkerGateway(text, { app, accessAud } = {}) {
  assertAppName(app);
  assertDeployValue("accessAud", accessAud);
  const replaceCount = countMatches(text, /"REPLACE"/g);
  if (replaceCount !== 1) {
    throw new Error(`expected exactly 1 "REPLACE" marker (ACCESS_AUD) in the worker gateway config, found ${replaceCount}`);
  }
  const out = applyMarkers(text, [
    { pattern: /"inno-app-replace-app"/, replacement: `"inno-app-${app}-app"` },
    { pattern: /"inno-app-replace"/, replacement: `"inno-app-${app}"` },
    { pattern: /("ACCESS_AUD"\s*:\s*)"REPLACE"/, replacement: `$1"${accessAud}"` },
  ]);
  return forceProductionEnvironment(forceWorkersDevFalse(out, "worker gateway config"), "worker gateway config");
}

/**
 * Template the mcp-type GATEWAY config (gateway/wrangler.mcp.jsonc).
 * Same marker discipline as templateWorkerGateway, but the single "REPLACE" is
 * OAUTH_RS_RESOURCE (this app's RFC 8707/9728 resource identifier) rather than
 * ACCESS_AUD — mcp apps have no Cloudflare Access application. The resource is
 * compared by EXACT match against a token's audience, so it is validated as a
 * deploy value and must arrive from the broker's `oauth_rs_resource`, never be
 * rebuilt here.
 */
export function templateMcpGateway(text, { app, mcpResource } = {}) {
  assertAppName(app);
  assertDeployValue("mcpResource", mcpResource);
  const replaceCount = countMatches(text, /"REPLACE"/g);
  if (replaceCount !== 1) {
    throw new Error(`expected exactly 1 "REPLACE" marker (OAUTH_RS_RESOURCE) in the mcp gateway config, found ${replaceCount}`);
  }
  const out = applyMarkers(text, [
    { pattern: /"inno-app-replace-app"/, replacement: `"inno-app-${app}-app"` },
    { pattern: /"inno-app-replace"/, replacement: `"inno-app-${app}"` },
    { pattern: /("OAUTH_RS_RESOURCE"\s*:\s*)"REPLACE"/, replacement: `$1"${mcpResource}"` },
  ]);
  return forceProductionEnvironment(forceWorkersDevFalse(out, "mcp gateway config"), "mcp gateway config");
}

/**
 * Template the mcp-container GATEWAY config (gateway/wrangler.mcp-container.jsonc)
 * — the container × oauth-rs preset. This gateway HOLDS its own D1/R2 directly
 * (no separate app-worker config, same as the plain container gateway), so it
 * reuses the default container mode's name/D1/R2/linked-databases
 * substitutions; the only swap versus that mode is the identity marker —
 * OAUTH_RS_RESOURCE (this app's RFC 8707/9728 resource identifier) instead of
 * ACCESS_AUD, because these apps have no Cloudflare Access application. Same
 * exactly-one-marker corruption guard and empty-value refusal as
 * templateMcpGateway, scoped to the OAUTH_RS_RESOURCE key so it doesn't
 * collide with the also-present database_id REPLACE marker (unlike
 * wrangler.mcp.jsonc, this variant carries d1_databases too).
 *
 * @param {string} text
 * @param {{app: string, databaseId: string, resource: string, image?: string, linkedDatabases?: {binding: string, databaseName: string, databaseId: string, generation: string | null}[]}} params
 * @returns {string} the substituted JSONC text
 */
export function templateMcpContainerGateway(text, { app, databaseId, resource, image, linkedDatabases = [] } = {}) {
  assertAppName(app);
  assertDeployValue("databaseId", databaseId);
  assertDeployValue("resource", resource);
  const imageValue = containerImageValue({ image });

  const resourceMarkerCount = countMatches(text, /"OAUTH_RS_RESOURCE"\s*:\s*"REPLACE"/g);
  if (resourceMarkerCount !== 1) {
    throw new Error(
      `expected exactly 1 "OAUTH_RS_RESOURCE" REPLACE marker in the mcp-container gateway config, found ${resourceMarkerCount}`,
    );
  }

  // Belt-and-suspenders, mirroring templateWrangler's own safety net: this
  // variant (unlike wrangler.mcp.jsonc) carries d1_databases too, so it must
  // have exactly two bare `"REPLACE"` literal occurrences total (database_id,
  // OAUTH_RS_RESOURCE). Checked AFTER the scoped check above so a corrupted
  // OAUTH_RS_RESOURCE marker still reports "found 0" against that specific
  // key rather than being masked by this total falling to 1. This one instead
  // catches a hypothetical THIRD marker added to the variant later — neither
  // scoped check above would notice an extra "REPLACE" elsewhere.
  const replaceLiteralCount = countMatches(text, /"REPLACE"/g);
  if (replaceLiteralCount !== 2) {
    throw new Error(
      `expected exactly 2 "REPLACE" markers (database_id, OAUTH_RS_RESOURCE) in the mcp-container gateway config, found ${replaceLiteralCount}`,
    );
  }

  const out = applyMarkers(text, [
    { pattern: /"inno-app-replace"/, replacement: `"inno-app-${app}"` },
    { pattern: /"inno-replace-db"/, replacement: `"inno-${app}-db"` },
    { pattern: /("database_id"\s*:\s*)"REPLACE"/, replacement: `$1"${databaseId}"` },
    { pattern: /"inno-replace-data"/, replacement: `"inno-${app}-data"` },
    { pattern: /("OAUTH_RS_RESOURCE"\s*:\s*)"REPLACE"/, replacement: `$1"${resource}"` },
    { pattern: /("image"\s*:\s*)"\.\/Dockerfile"/, replacement: `$1"${imageValue}"` },
  ]);

  // Cross-app data links (migration 0028): the gateway holds these bindings
  // directly for a container app (it has no credential of its own to reach
  // storage), same as the default container mode.
  const withLinks = appendLinkedDatabases(out, linkedDatabases, "mcp-container gateway config");
  const withGenerations = appendLinkGenerationVars(withLinks, linkedDatabases, "mcp-container gateway config");
  return forceProductionEnvironment(forceWorkersDevFalse(withGenerations, "mcp-container gateway config"), "mcp-container gateway config");
}

/**
 * Template the function-shape APP WORKER config (gateway/app-worker.jsonc).
 * Markers: the worker name ("inno-app-replace-app"), D1 name/id, R2 bucket.
 * Exactly one "REPLACE" (database_id) — no ACCESS_AUD (the gateway owns Access).
 *
 * @param {string} text
 * @param {{app: string, databaseId: string, linkedDatabases?: {binding: string, databaseName: string, databaseId: string}[]}} params
 * @returns {string} the substituted JSONC text
 */
export function templateWorkerApp(text, { app, databaseId, linkedDatabases = [] } = {}) {
  assertAppName(app);
  assertDeployValue("databaseId", databaseId);
  const replaceCount = countMatches(text, /"REPLACE"/g);
  if (replaceCount !== 1) {
    throw new Error(`expected exactly 1 "REPLACE" marker (database_id) in the app worker config, found ${replaceCount}`);
  }
  const out = applyMarkers(text, [
    { pattern: /"inno-app-replace-app"/, replacement: `"inno-app-${app}-app"` },
    { pattern: /"inno-replace-db"/, replacement: `"inno-${app}-db"` },
    { pattern: /"inno-replace-data"/, replacement: `"inno-${app}-data"` },
    { pattern: /("database_id"\s*:\s*)"REPLACE"/, replacement: `$1"${databaseId}"` },
  ]);
  // Cross-app data links (migration 0028): each becomes an EXTRA D1 binding
  // alongside the app's own DATA. Appended after marker substitution so the
  // marker post-conditions above see only the template's own values.
  const withLinks = appendLinkedDatabases(out, linkedDatabases, "app worker config");
  return forceWorkersDevFalse(withLinks, "app worker config");
}

if (isMainModule(import.meta.url)) {
  const [mode, ...rest] = process.argv.slice(2);
  // Linked databases arrive as JSON in the environment rather than argv: the
  // payload is a nested structure and every shell-quoting mistake here would be
  // a config-corruption bug. Empty/absent is the common case.
  const linkedDatabases = parseLinkedDatabases(process.env.INNO_LINKED_DATABASES);
  // Digest-pinned registry reference for the already-scanned, already-pushed
  // image (R11). The ONLY accepted image source for a container-shaped
  // deploy — containerImageValue refuses outright when this is empty; there
  // is no Dockerfile-path fallback any more (I-4 fix round).
  const image = process.env.INNO_IMAGE;
  // Announced by the modes that actually consume the links, not at parse time:
  // a function-shaped deploy templates the gateway AND the app Worker from the
  // same environment, and only the app Worker binds the linked databases, so
  // announcing once per invocation printed the line twice for one deploy, once
  // for a config that linked nothing.
  const announceLinks = () => {
    if (linkedDatabases.length > 0) {
      console.log(`linking ${linkedDatabases.length} cross-app database(s): ${linkedDatabases.map((l) => l.binding).join(", ")}`);
    }
  };
  if (mode === "--worker-gateway") {
    const [app, accessAud, path = "wrangler.jsonc"] = rest;
    if (!app || !accessAud) { console.error("Usage: node ci/template-wrangler.mjs --worker-gateway <app> <accessAud> [path]"); process.exit(1); }
    writeFileSync(path, templateWorkerGateway(readFileSync(path, "utf8"), { app, accessAud }));
    console.log(`templated worker gateway ${path} for app "${app}"`);
  } else if (mode === "--mcp-gateway") {
    const [app, mcpResource, path = "wrangler.jsonc"] = rest;
    if (!app || !mcpResource) { console.error("Usage: node ci/template-wrangler.mjs --mcp-gateway <app> <mcpResource> [path]"); process.exit(1); }
    writeFileSync(path, templateMcpGateway(readFileSync(path, "utf8"), { app, mcpResource }));
    console.log(`templated mcp gateway ${path} for app "${app}"`);
  } else if (mode === "--mcp-container-gateway") {
    const [app, databaseId, resource, path = "wrangler.jsonc"] = rest;
    if (!app || !databaseId || !resource) { console.error("Usage: node ci/template-wrangler.mjs --mcp-container-gateway <app> <databaseId> <resource> [path]"); process.exit(1); }
    announceLinks();
    writeFileSync(path, templateMcpContainerGateway(readFileSync(path, "utf8"), { app, databaseId, resource, image, linkedDatabases }));
    console.log(`templated mcp-container gateway ${path} for app "${app}"`);
  } else if (mode === "--worker-app") {
    const [app, databaseId, path = "wrangler.jsonc"] = rest;
    if (!app || !databaseId) { console.error("Usage: node ci/template-wrangler.mjs --worker-app <app> <databaseId> [path]"); process.exit(1); }
    announceLinks();
    writeFileSync(path, templateWorkerApp(readFileSync(path, "utf8"), { app, databaseId, linkedDatabases }));
    console.log(`templated app worker ${path} for app "${app}"`);
  } else {
    const [app, databaseId, accessAud, wranglerPath = "wrangler.jsonc"] = [mode, ...rest];
    if (!app || !databaseId || !accessAud) {
      console.error("Usage: node ci/template-wrangler.mjs <app> <databaseId> <accessAud> [wranglerPath=wrangler.jsonc]");
      process.exit(1);
    }
    announceLinks();
    const templated = templateWrangler(readFileSync(wranglerPath, "utf8"), { app, databaseId, accessAud, image, linkedDatabases });
    writeFileSync(wranglerPath, templated);
    console.log(`templated ${wranglerPath} for app "${app}"`);
  }
}
