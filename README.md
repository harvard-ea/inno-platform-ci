# inno-platform-ci

The Innovation Platform's **public CI contract**: the reusable safety-gate +
deploy workflow (`.github/workflows/platform-ci.yml`), the gate scripts it
runs (`ci/`), and the pinned build tools the deploy job installs
(`ci/build/`).

**This repo is a generated mirror (do not open PRs here).** Source of truth,
tests, and review happen in the private `inno-platform` repo; every commit
here is `publish: inno-platform@<sha>`, pushed automatically by its CI.

App repos consume it with `.github/workflows/deploy.yml`:

```yaml
name: deploy
on:
  push:
    branches: [main]
    tags: ["v*"]
  workflow_dispatch: {}
permissions:
  id-token: write
  contents: read
jobs:
  platform:
    uses: harvard-ea/inno-platform-ci/.github/workflows/platform-ci.yml@main
    with:
      app: <your-app-name>
```

Four things about that file are load-bearing:

- **`@main` is the only accepted ref.** The deploy broker compares the OIDC
  token's signed `job_workflow_ref` claim against this exact string; a SHA, a
  tag, or a fork is refused with `deploy_denied:workflow`. Do not pin it.
- **The filename must be `deploy.yml` and `workflow_dispatch: {}` must stay.**
  The platform dispatches `deploy.yml` by name to rebuild your app: a security
  respin (a CVE fix), a rebuild (an admin's, or the platform's own after a data
  link is revoked) and the panel's redeploy; strip the trigger and every one of
  them fails with a 422.
- **`with: app:`** names your registered app. Unset, the workflow falls back to
  deriving it from the repo name.
- **`branches: [main]` above is only an example.** Registration generates your
  `deploy.yml` with the repo's own default branch, so a `master` repo gets
  `branches: [master]`. Copy this sample onto such a repo verbatim and pushes
  to its default branch run no preflight at all.

Pushing to `main` runs the safety gates only; pushing a `v*` tag deploys.

The workflow is intentionally safe to call from untrusted repos: **provenance
is enforced server-side**: the deploy broker verifies the signed OIDC
`job_workflow_ref`, `repository_id`, and `ref` claims and starts a deploy for
nothing else, and the gates themselves run inside this reusable workflow,
which a calling repo cannot edit.

Licensed MIT-0 (see LICENSE), same as the app template; the contract is meant
to be consumed and, for your own platform deployment, adapted without
attribution burden.
