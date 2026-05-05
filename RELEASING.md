# Releasing rust-gvm

All releases are managed via [clawosiris/release-orchestrator](https://github.com/clawosiris/release-orchestrator).

## How It Works

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        release-orchestrator                              │
│  (workflow_dispatch)                                                     │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │ triggers via greenbone/actions/trigger-workflow
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    release-orchestrated.yml                              │
│  1. Creates release via pontos (changelog, version bump, GitHub release) │
│  2. Pushes tag v<version>                                                │
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

## Release Types

| Type | Command | Example Version |
|------|---------|-----------------|
| Patch | `patch` | `0.4.1` |
| Minor | `minor` | `0.5.0` |
| Major | `major` | `1.0.0` |
| Alpha | `alpha: true` | `0.5.0-alpha.1` |
| Release Candidate | `release-candidate: true` | `0.5.0-rc.1` |

## Do NOT

- **Do NOT** trigger `release-orchestrated.yml` manually — it's designed for orchestrator use
- **Do NOT** push version tags manually — let pontos handle it
- **Do NOT** create GitHub releases manually — pontos + release.yml handle everything

## Release Artifacts

Each release includes:

- **Binaries**: `gvm-mock-server` for Linux (amd64, arm64, musl), macOS (amd64, arm64)
- **Docker image**: `ghcr.io/clawosiris/gvm-mock-server:<version>`
- **SBOM**: CycloneDX JSON/XML with quality scoring
- **Attestations**: Sigstore build provenance for all artifacts

## Verifying Artifacts

```bash
gh attestation verify gvm-mock-server-linux-amd64.tar.gz --owner clawosiris
```
