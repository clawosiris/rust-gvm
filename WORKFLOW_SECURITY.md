# Workflow Security Audit

This document tracks the security posture of GitHub Actions used in this repository, assessed via [OpenSSF Scorecard](https://securityscorecards.dev/).

## Audit Summary

**Audit Date:** 2026-03-31
**Scorecard Version:** v5.4.0

### Results

| Action | Score | Code-Review | Branch-Prot | Token-Perms | Dangerous-WF | CI-Tests | Maintained |
|--------|-------|-------------|-------------|-------------|--------------|----------|------------|
| actions/checkout | 5.6 | 10 | 5 | 0 | 10 | 5 | 2 |
| actions/setup-python | 5.1 | 10 | 0 | 0 | 10 | 10 | 2 |
| actions/attest-build-provenance | 9.3 | 10 | 6 | 10 | 10 | 10 | 10 |
| dtolnay/rust-toolchain | 5.6 | 0 | 3 | 10 | 10 | 10 | 2 |
| Swatinem/rust-cache | 7.4 | 5 | 0 | 10 | 10 | 10 | 10 |
| step-security/harden-runner | 9.6 | 10 | 8 | 10 | 10 | 10 | 10 |
| taiki-e/install-action | 7.2 | 0 | 4 | 10 | 10 | 10 | 10 |
| codecov/codecov-action | 6.6 | 10 | 6 | 0 | 10 | 9 | 5 |
| softprops/action-gh-release | 4.7 | 0 | 0 | 0 | 10 | 10 | 10 |
| docker/setup-qemu-action | 9.3 | 10 | 6 | 10 | 10 | 10 | 10 |
| docker/setup-buildx-action | 9.3 | 10 | 6 | 10 | 10 | 10 | 10 |
| docker/login-action | 9.3 | 10 | 6 | 10 | 10 | 10 | 10 |
| docker/metadata-action | 9.3 | 10 | 6 | 10 | 10 | 10 | 10 |
| docker/build-push-action | 9.3 | 10 | 6 | 10 | 10 | 10 | 10 |
| EmbarkStudios/cargo-deny-action | 4.0 | 2 | 6 | 0 | 10 | 4 | 0 |

### Score Legend

- **Code-Review:** Are PRs reviewed before merge?
- **Branch-Prot:** Are main branches protected?
- **Token-Perms:** Does action request minimal permissions?
- **Dangerous-WF:** Does it avoid arbitrary code execution patterns?
- **CI-Tests:** Is there test coverage?
- **Maintained:** Is the project actively maintained?

Scores range from 0-10; higher is better.

---

## Flagged Actions (Score < 6.0)

The following actions scored below 6.0 and warrant attention:

### 1. EmbarkStudios/cargo-deny-action — Score: 4.0

**Issues:**
- **Maintained: 0** — No recent commits; Embark Studios has reduced open source activity
- **Token-Permissions: 0** — Requests broad permissions
- **Code-Review: 2** — Minimal review process
- **CI-Tests: 4** — Limited test coverage

**Risk Assessment:** Medium-High. The action is unmaintained. While it's pinned by commit SHA, upstream security patches won't arrive.

**Recommendation:** Consider alternatives:
- Run `cargo deny check` directly in workflow (no action dependency)
- Fork and maintain internally if needed

### 2. softprops/action-gh-release — Score: 4.7

**Issues:**
- **Code-Review: 0** — No formal review process
- **Branch-Protection: 0** — Main branch unprotected
- **Token-Permissions: 0** — Requests broad permissions

**Risk Assessment:** Medium. The action is actively maintained (10) but lacks security controls.

**Recommendation:** 
- Continue using with commit SHA pinning
- Monitor for security advisories
- Consider `gh release create` as CLI alternative

### 3. dtolnay/rust-toolchain — Score: 5.6

**Issues:**
- **Code-Review: 0** — Single-maintainer project without formal review
- **Maintained: 2** — Lower commit frequency
- **Branch-Protection: 3** — Limited branch protection

**Risk Assessment:** Low-Medium. David Tolnay is a highly trusted Rust ecosystem maintainer. The low scores reflect single-maintainer governance, not security concerns.

**Recommendation:** Accept risk; dtolnay's track record is excellent. Continue SHA pinning.

### 4. actions/checkout — Score: 5.6

**Issues:**
- **Token-Permissions: 0** — Inherently requires repo access
- **Maintained: 2** — Stable, fewer updates needed

**Risk Assessment:** Low. This is a GitHub first-party action. The token permissions score reflects its core function (checking out code requires repo access). Low maintenance score indicates stability, not abandonment.

**Recommendation:** Continue using; this is unavoidable and trustworthy.

### 5. actions/setup-python — Score: 5.1

**Issues:**
- **Token-Permissions: 0** — Requests broad permissions
- **Branch-Protection: 0** — Limited branch protection
- **Maintained: 2** — Stable, fewer updates

**Risk Assessment:** Low. GitHub first-party action. Same pattern as checkout—stable infrastructure with low churn.

**Recommendation:** Continue using; trustworthy despite low scorecard metrics.

---

## High-Scoring Actions (Score ≥ 9.0)

These actions demonstrate excellent security posture:

| Action | Score | Notes |
|--------|-------|-------|
| step-security/harden-runner | 9.6 | Security-focused org; excellent practices |
| docker/* actions | 9.3 | Docker official; well-maintained |
| actions/attest-build-provenance | 9.3 | GitHub first-party; SLSA attestation |

---

## Mitigation Strategies

### All Actions

1. **SHA Pinning:** All actions are pinned to full commit SHAs (not tags)
2. **Dependabot:** Monitors for action updates
3. **harden-runner:** Applied to sensitive workflows

### For Flagged Actions

1. **cargo-deny-action:** Evaluate direct CLI usage in next workflow revision
2. **action-gh-release:** Monitor; CLI fallback available
3. **Single-maintainer actions:** Accept informed risk; these are ecosystem standards

---

## Next Audit

Schedule: Quarterly or after major workflow changes.

Run scorecard manually:
```bash
scorecard --repo github.com/<org>/<action> --checks Code-Review,Branch-Protection,Token-Permissions,Dangerous-Workflow,CI-Tests,Maintained
```
