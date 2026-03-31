# Releasing

This repository uses orchestrated releases via [clawosiris/release-orchestrator](https://github.com/clawosiris/release-orchestrator).

## How Releases Work

1. **Do NOT create releases manually** in this repository
2. All releases are triggered from the [release-orchestrator](https://github.com/clawosiris/release-orchestrator)
3. The orchestrator manages versioning, changelogs, and cross-repo coordination

## Creating a Release

### Stable Release
1. Go to [release-orchestrator](https://github.com/clawosiris/release-orchestrator)
2. Trigger the release workflow with type `patch`, `minor`, or `major`

### Nightly / Alpha Build
1. Go to [release-orchestrator](https://github.com/clawosiris/release-orchestrator)
2. Trigger the release workflow with type `alpha`

### Pre-releases
- `alpha` — Early development builds (nightlies)
- `beta` — Feature-complete, testing phase
- `release-candidate` — Final testing before stable

## Local Development

For local testing without releasing:
```bash
cargo build --release
cargo test
```

## Questions?

See the [release-orchestrator README](https://github.com/clawosiris/release-orchestrator) for full documentation.
