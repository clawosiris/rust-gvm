# Releasing rust-gvm

Releases are managed via the repository's
[Orchestrated Release workflow](https://github.com/greenbone-hive/rust-gvm/actions/workflows/release-orchestrated.yml).

## How It Works

First, update `[workspace.package].version` and `Cargo.lock` in a normal pull
request. Merge that pull request through the protected `main` branch after all
required review and checks pass. Then dispatch the release workflow with that
exact version.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Protected main                                    │
│  Version and Cargo.lock update merged through a reviewed pull request    │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │ workflow_dispatch with the exact merged version
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    release-orchestrated.yml                              │
│  1. Validates the version already merged through protected main          │
│  2. Creates the changelog, tag, and GitHub release via pontos            │
│  3. Waits for release.yml to complete                                    │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │ tag push triggers
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         release.yml                                      │
│  1. Runs tests                                                           │
│  2. Builds gvm-mock-server binaries (5 platforms)                        │
│  3. Publishes Docker image to GHCR                                       │
│  4. Generates SBOM (CycloneDX)                                           │
│  5. Uploads all artifacts to the GitHub release                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Versioning

The workflow accepts the exact semantic version already merged to `main`.
Versions containing a pre-release suffix, such as `0.6.0-alpha.1` or
`0.6.0-rc.1`, are published as GitHub pre-releases automatically.

## Do NOT

- **Do NOT** dispatch a version that is not already merged to `main`
- **Do NOT** push version tags manually — let pontos handle it
- **Do NOT** create GitHub releases manually — pontos + release.yml handle everything

## Release Artifacts

Each release includes:

- **Binaries**: `gvm-mock-server` for Linux (amd64, arm64, musl), macOS (amd64, arm64)
- **Docker image**: `ghcr.io/greenbone-hive/gvm-mock-server:<version>`
- **SBOM**: CycloneDX JSON/XML with quality scoring
- **Attestations**: Sigstore build provenance for all artifacts

## Verifying Artifacts

```bash
gh attestation verify gvm-mock-server-linux-amd64.tar.gz --owner greenbone-hive
```
