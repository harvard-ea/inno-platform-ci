#!/usr/bin/env node
// Uploads the container job's freshly generated CycloneDX SBOM to the
// platform broker's /deploy-sbom endpoint, which STAGES it keyed by this
// run's verified OIDC run_id claim. /deploy-complete (same run) later
// promotes it to the app's live SBOM pointer, so the safety sweep always
// scans what actually deployed.
//
// `imageId` (R11) is the scanned image's own config digest
// (`docker image inspect --format '{{.Id}}'`), staged alongside the SBOM so
// the deploy job can prove it later loaded and pushed that SAME image rather
// than a rebuild.
//
// Not best-effort (R7-1, v0.17.4): this upload is the one place a run records
// the scanned image's id, and the broker refuses the deploy job's token
// request for a run that recorded none. So the CLI fails its step on any
// failure and exits 1, reporting it as the token, finalize and bundle CLIs
// do (ci/broker-post.mjs reportRefusal, R7-deploy-ci-7): the message plainly
// on stderr, then one error annotation titled "SBOM upload failed" (ci/cli.mjs
// annotate, which flattens it, so a refusal's text cannot start a workflow
// command of its own). A refusal that carries the broker's own sentence
// (sbom_too_large, app_stopped, repo_unlinked) says what to do, so the
// sentence is the annotation's fix and the CLI adds no remedy of its own: for
// an SBOM over the cap, re-running the release's workflow would rebuild the
// same image and meet the same refusal. Any other failure (no answer, a
// refusal with no sentence, an unreadable SBOM file) ends with the CLI's
// remedy, re-running the release's workflow. The tenant workflow runs it on a
// release tag only (platform-ci.yml, "Upload SBOM and image id to broker").
//
// Usage: node ci/sbom-upload.mjs <brokerUrl> <app> <sbomPath> <token> [imageId]
// `token` is the GitHub Actions OIDC token (verified server-side).

import { readFile } from "node:fs/promises";
import { brokerPost, reportRefusal } from "./broker-post.mjs";
import { isMainModule, logSafe } from "./cli.mjs";

/**
 * POST {app, sbom, image_id?} to `${base}/deploy-sbom`, authenticated with the
 * GitHub Actions OIDC token. The fields are one options object, as every ci/
 * broker helper's are, so an injected fetcher can never land in an optional
 * field's slot.
 *
 * @param {object} req
 * @param {string} req.base - broker base URL
 * @param {string} req.token - GitHub Actions OIDC token
 * @param {string} req.app
 * @param {object} req.sbom - parsed CycloneDX document
 * @param {string} [req.imageId] - the scanned image's config digest (R11); no field when empty
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} [fetcher]
 *   - injectable for testing; defaults to global fetch
 * @returns {Promise<any>} the parsed JSON response body (e.g. { stored })
 */
export async function uploadSbom({ base, token, app, sbom, imageId }, fetcher = fetch) {
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
    const result = await uploadSbom({ base, token, app, sbom, imageId });
    // The step prints this line to its log as it is, so the broker's answer
    // is flattened (logSafe breaks the runner's ##[ marker too).
    console.log(`deploy-sbom: ${logSafe(JSON.stringify(result), Infinity)}`);
  } catch (err) {
    const raw = String(err?.message ?? err);
    if (raw.startsWith("Usage:")) {
      console.error(raw);
    } else {
      reportRefusal(err, {
        label: "deploy-sbom",
        title: "SBOM upload failed",
        fix: "this release cannot deploy without it: fix what the message names, then re-run the release's workflow",
      });
    }
    process.exitCode = 1;
  }
}
