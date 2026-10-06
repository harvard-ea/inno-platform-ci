#!/usr/bin/env node
// Turns a wrangler bundle failure that says only `Could not resolve
// "<specifier>"` into an error annotation that names the package and the fix
// (OPEN 33).
//
// Usage: node ci/explain-unresolved.mjs <wrangler-log> <app/package.json>
//
// Since platform v0.14.21 the app-deps job installs a function-shaped app's
// dependencies with `npm ci --ignore-scripts --omit=dev`, so the tree the
// deploy bundles is exactly the tree the dependency gate audited. What that
// buys is a failure the platform previously shipped past: production code
// that imports a devDependency. It now stops wrangler's bundle in the deploy
// job, which is the truth arriving at the right time, but the only evidence
// is esbuild's one-line module-not-found, printed inside a reusable workflow
// whose source the app author cannot read. Hence this: the same line, said in
// terms of the author's own app/package.json.
//
// It explains, it never judges. Exit status is 0 in every case (the deploy
// step's own `exit 1` is what fails the run, so a non-zero exit here would
// only mask wrangler's failure with the explainer's), and it prints nothing
// at all when there is nothing to explain: no unresolved line in the log, a
// log it cannot read, or an unresolved package that is already a production
// dependency, which means the bundle failed for some other reason.
//
// Imports nothing from src/. ci/*.mjs is a separate, zero-dependency build
// published to the public inno-platform-ci mirror and run on third-party
// runners, where only `node:` modules are available.

import { readFileSync } from "node:fs";

// wrangler surfaces esbuild's wording verbatim, in double quotes
// (`✘ [ERROR] Could not resolve "vitest"`), sometimes followed by a resolved
// path in parentheses. Single quotes are accepted too, so a bundler-wording
// change that only swaps the quote character does not silently stop the
// explanation.
const UNRESOLVED = /Could not resolve ["']([^"'\n]+)["']/g;

// A valid npm package name: an optional @scope/ prefix, then a name, with
// each component starting with a lowercase letter or digit and continuing
// with those plus "-", ".", "_" or "~". A tsconfig-paths alias such as "~"
// or "@/lib/x" never matches this, so packageOf below returns null for it
// instead of an "npm install" that cannot succeed.
const NPM_NAME = /^(@[a-z0-9][a-z0-9-._~]*\/)?[a-z0-9][a-z0-9-._~]*$/;

/**
 * The package a bundler specifier belongs to, or null when the specifier is
 * not a package at all. A scoped specifier keeps `@scope/name`; a deep import
 * keeps only the package part (`lodash/fp` is `lodash`); a relative or
 * absolute path is nobody's dependency and is skipped, and so is anything
 * left over that does not parse as an npm package name.
 *
 * @param {string} spec - the specifier as the bundler printed it
 * @returns {string|null}
 */
function packageOf(spec) {
  if (spec.startsWith(".") || spec.startsWith("/")) return null;
  // A scheme-prefixed specifier (node:fs, node:fs/promises, cloudflare:workers,
  // data:, http:) is a runtime builtin or a URL, never an npm package. The
  // usual cause of an unresolved node: import is a missing nodejs_compat flag,
  // and "npm install node:fs" is not a command that can succeed.
  const head = spec.split("/")[0];
  if (head.includes(":")) return null;
  const parts = spec.split("/");
  const pkg = spec.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
  return NPM_NAME.test(pkg) ? pkg : null;
}

/** The file's text, or "" when it cannot be read (see the exit-0 rule above). */
function readOrEmpty(path) {
  if (!path) return "";
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

const [, , logPath, manifestPath] = process.argv;
const log = readOrEmpty(logPath);

let manifest = {};
try {
  const parsed = JSON.parse(readOrEmpty(manifestPath));
  if (parsed && typeof parsed === "object") manifest = parsed;
} catch {
  // An app/package.json that is absent or unparseable declares nothing, which
  // is exactly what the "not declared anywhere" branch below says.
}
// optionalDependencies is installed by npm ci --omit=dev same as dependencies,
// so a package declared only there is silent, not "not declared", like a
// production dependency.
const prod = { ...(manifest.dependencies ?? {}), ...(manifest.optionalDependencies ?? {}) };
const dev = manifest.devDependencies ?? {};

// First-seen order, one annotation per package: wrangler names the same
// package once per import site, and three copies of one explanation is noise
// the author has to read past to find the second problem.
const seen = new Set();
for (const m of log.matchAll(UNRESOLVED)) {
  const pkg = packageOf(m[1]);
  if (pkg === null || seen.has(pkg)) continue;
  seen.add(pkg);
  // Already a production dependency, so --omit=dev is not why this failed.
  // Saying anything here would send the author after the wrong cause.
  if (Object.prototype.hasOwnProperty.call(prod, pkg)) continue;
  if (Object.prototype.hasOwnProperty.call(dev, pkg)) {
    console.log(
      `::error title=devDependency imported at runtime::"${pkg}" is declared under devDependencies in `
      + "app/package.json but your production code imports it. Since platform v0.14.21 the deploy installs "
      + `production dependencies only (npm ci --omit=dev), so it is not present at bundle time. Move it: cd app `
      + `&& npm install ${pkg} && npm uninstall --save-dev ${pkg}, commit app/package.json and `
      + "app/package-lock.json, then tag again. The dependency gate will audit it from then on.",
    );
  } else {
    console.log(
      `::error title=Undeclared import::"${pkg}" is imported by your production code but not declared in `
      + `app/package.json. Declare it: cd app && npm install ${pkg}, commit both manifest files, then tag again.`,
    );
  }
}
