# CI, container images and releases

This repository publishes container images to GitHub Container Registry (GHCR) and creates GitHub Releases from the version in `src/package.json`.

## Pull request validation

Every pull request runs `.github/workflows/lint.yml`:

- Installs dependencies with `npm ci`.
- Runs ESLint.
- Verifies that the generated Vue template is current.
- Runs the Jest suite serially.

When a pull request changes `src/**`, `Dockerfile` or `.dockerignore`, `.github/workflows/deploy-pr.yml` also builds the image for `linux/amd64` and `linux/arm64`. The pull request build is never pushed.

## Images generated from main

Every push to `main` that changes `src/**`, `Dockerfile` or `.dockerignore` runs `.github/workflows/deploy.yml`. The workflow validates the source before publishing a multi-architecture image.

Each successful build publishes:

- `ghcr.io/ydtoloza/wg-easy-port-manager:main`: mutable pointer to the latest validated code commit.
- `ghcr.io/ydtoloza/wg-easy-port-manager:sha-<full commit>`: immutable image for that exact commit. Existing commit tags are detected and never rebuilt by CI.

Documentation-only and Compose-only commits do not rebuild the image because they do not change its contents.

If one push contains multiple code-changing commits, the workflow enumerates the pushed range and builds each commit sequentially. Separate pushes may run concurrently; before updating `main`, each workflow verifies that its head is still the current remote branch tip so an older run cannot move `main` backwards.

## Stable release tags

Pushing a semantic version tag such as `v2.0.0` starts `.github/workflows/release.yml`. The workflow requires the Git tag, package version and application release version to match before it publishes:

- Full version, for example `2.0.0`.
- Major/minor alias, for example `2.0`.
- Major alias, for example `2`.
- `latest`.

It then creates or updates the GitHub Release associated with that tag. Normal commits never update stable tags.

Version 2.0 uses:

- Package version: `2.0.0`.
- Git tag: `v2.0.0`.
- GitHub Release name: `WG-Easy Port Manager 2.0`.
- Release notes: `docs/releases/v2.0.0.md`.

## Preparing a future release

1. Update `version` and `release.version` in `src/package.json`.
2. Update the root package entries in `src/package-lock.json`.
3. Add `docs/releases/v<version>.md` with highlights and migration warnings.
4. Set the recommended `IMAGE_TAG` in `.env.example` and `docker-compose.yml`.
5. Run the local validation commands documented in `docs/security-and-operations.md`.
6. Merge or push the release commit to `main` and wait for its commit image to succeed.
7. Create one annotated tag on that exact commit and push it:

```sh
git tag -a v2.1.0 -m "Release 2.1.0"
git push origin v2.1.0
```

The tag workflow publishes the stable image aliases and the GitHub Release. Protect the `v*` tag namespace with a repository ruleset so only maintainers can create or delete release tags.

## Repository requirements

- GitHub Actions must be enabled.
- The workflow token must be allowed to write repository contents and packages. The publish job requests `contents: write` and `packages: write` explicitly.
- The GHCR package should be public for anonymous VPS pulls. If it is private, authenticate Docker on the VPS with a read-only package token.
- Protect release tags against deletion and retargeting.

The workflow publishes images but does not connect to or mutate a VPS. Production deployment remains an explicit operation using a stable or immutable image tag; see [VPS deployment](vps-deployment.md).
