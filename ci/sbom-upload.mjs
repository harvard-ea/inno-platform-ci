#!/usr/bin/env node
// Uploads the container job's freshly generated CycloneDX SBOM to the
// platform broker's /deploy-sbom endpoint, which STAGES it keyed by this
// run's verified OIDC run_id claim. /deploy-complete (same run) later
// promotes it to the app's live SBOM pointer, so the safety sweep always
// scans what actually deployed. Best-effort in CI: a failed upload warns and
// the build proceeds (the sweep keeps using the previous deployment's SBOM).
//
// `imageId` (R11) is the scanned image's own config digest
// (`docker image inspect --format '{{.Id}}'`), staged alongside the SBOM so
// the deploy job can prove it later loaded and pushed that SAME image rather
// than a rebuild.
//
// Usage: node ci/sbom-upload.mjs <brokerUrl> <app> <sbomPath> <token> [imageId]
// `token` is the GitHub Actions OIDC token (verified server-side).

import { readFile } from "node:fs/promises";
import { brokerPost } from "./broker-post.mjs";
import { isMainModule } from "./cli.mjs";

/**
 * POST {app, sbom, image_id?} to `${base}/deploy-sbom`, authenticated with the
 * GitHub Actions OIDC token.
 *
 * @param {string} base - broker base URL
 * @param {string} token - GitHub Actions OIDC token
 * @param {string} app
 * @param {object} sbom - parsed CycloneDX document
 * @param {string} [imageId] - the scanned image's config digest (R11)
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} fetcher
 *   - injectable for testing; defaults to global fetch
 * @returns {Promise<any>} the parsed JSON response body (e.g. { stored })
 */
export async function uploadSbom(base, token, app, sbom, imageId, fetcher = fetch) {
  return brokerPost(
    { base, path: "/deploy-sbom", label: "deploy-sbom", token, body: { app, sbom, ...(imageId ? { image_id: imageId } : {}) } },
    fetcher,
  );
}

if (isMainModule(import.meta.url)) {
  try {
    const [base, app, sbomPath, token, imageId] = process.argv.slice(2);
    if (!base || !app || !sbomPath || !token) {
      throw new Error("Usage: node ci/sbom-upload.mjs <brokerUrl> <app> <sbomPath> <token> [imageId]");
    }
    let sbom;
    try {
      sbom = JSON.parse(await readFile(sbomPath, "utf8"));
    } catch (err) {
      throw new Error(`could not read/parse SBOM at ${sbomPath}: ${String(err?.message ?? err)}`);
    }
    const result = await uploadSbom(base, token, app, sbom, imageId);
    console.log(`deploy-sbom: ${JSON.stringify(result)}`);
  } catch (err) {
    console.error(String(err?.message ?? err));
    process.exitCode = 1;
  }
}
