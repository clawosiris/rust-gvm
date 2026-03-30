# Workflow Security Policy

This document defines the security requirements and practices for GitHub Actions workflows in this repository.

## Action Pinning

**All external actions MUST be pinned by full commit SHA**, not by tag or branch.

### Why?
- Tags can be force-pushed (attacker replaces `v2` with malicious code)
- SHA pins are immutable — the exact code you reviewed is what runs
- Protects against compromised upstream repos and supply chain attacks

### Format
```yaml
# ✅ Correct - pinned by SHA
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6

# ❌ Wrong - pinned by tag (can be moved)
- uses: actions/checkout@v6
```

### Updating Pinned Actions
When Dependabot proposes an action update:
1. Review the changelog for the action
2. Verify the SHA corresponds to a signed/verified release
3. Check if the action has OpenSSF Scorecard results
4. Merge only after validation

## Tool Version Pinning

**All `cargo install`, `go install`, and similar commands MUST specify versions.**

### Why?
- `@latest` or unpinned installs can pull malicious versions
- Reproducible builds require fixed dependencies
- Auditing requires knowing exactly what version ran

### Format
```yaml
# ✅ Correct - pinned versions
- uses: taiki-e/install-action@<sha>
  with:
    tool: cargo-audit@0.22.1

- run: go install github.com/interlynk-io/sbomqs@v2.0.5

- run: cargo install cross --git https://github.com/cross-rs/cross --tag v0.2.5

# ❌ Wrong - unpinned
- run: cargo install cargo-audit
- run: go install github.com/example/tool@latest
```

## Runtime Monitoring

All jobs use [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) for:
- Network egress monitoring (audit mode)
- Detection of anomalous outbound connections
- Supply chain attack detection

Currently in `audit` mode. After baseline is established, consider `block` mode for sensitive jobs.

## Build Provenance

Release and nightly builds generate [Sigstore attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) for:
- All binary artifacts (.tar.gz)
- SLSA Level 3 compliance

### Verifying Attestations
```bash
gh attestation verify gvm-mock-server-linux-amd64.tar.gz --owner clawosiris
```

## Permissions

Workflows follow least-privilege principle:
- Default: `contents: read` only
- `contents: write` only when creating releases/tags
- `packages: write` only when publishing containers
- `id-token: write` + `attestations: write` only for provenance generation

## Self-Hosted Runners

The Hetzner VPS runners (used for nightly/release builds) follow these practices:
- Separate user accounts per repo (isolation)
- No shared credentials between runners
- Runners in `docker` group for container builds
- Consider ephemeral runners for higher security (future)

## SBOM Generation

Every release includes CycloneDX SBOMs:
- Generated with pinned `cargo-cyclonedx` version
- Quality scored with `sbomqs` (minimum 7.0/10)
- Attached to releases for supply chain transparency

## Scheduled Security Scans

| Scan | Frequency | Tool |
|------|-----------|------|
| Rust advisories | Weekly + on push | `cargo-audit` |
| Dependency licenses | On push | `cargo-deny` |
| Unused dependencies | Weekly + on push | `cargo-machete` |

## Future Improvements

- [ ] Enable OpenSSF Scorecard when repo goes public
- [ ] Switch Harden-Runner to `block` mode after baseline
- [ ] Consider ephemeral self-hosted runners
- [ ] Add SLSA provenance for container images

## References

- [SLSA Framework](https://slsa.dev/)
- [OpenSSF Scorecard](https://securityscorecards.dev/)
- [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner)
- [Sigstore](https://sigstore.dev/)
- [GitHub Artifact Attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds)
