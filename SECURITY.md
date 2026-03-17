# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Current |

We support the latest minor release with security patches. Once a new minor or major version is published, prior versions receive patches only for critical vulnerabilities at maintainer discretion.

## Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Instead, use **GitHub Private Vulnerability Reporting**:

1. Go to the [Security Advisories](https://github.com/clawosiris/rust-gvm/security/advisories) tab
2. Click **"Report a vulnerability"**
3. Fill in the details — affected crate(s), reproduction steps, and impact assessment

Alternatively, contact the maintainers directly at: **[maintainer email / Signal contact — fill in]**

### What to expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 5 business days
- **Patch timeline** depends on severity:
  - **Critical / High**: Target fix within 7 days
  - **Medium**: Target fix within 30 days
  - **Low**: Next scheduled release
- We will coordinate disclosure timing with you. We follow [responsible disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure) practices.

### What qualifies

- Vulnerabilities in `gvm-protocol`, `gvm-gmp`, `gvm-client`, or `gvm-connection` crate code
- Authentication bypass or credential exposure in transport handling (SSH, Unix socket, TLS)
- XML parsing vulnerabilities (injection, XXE, billion-laughs)
- Memory safety issues
- Dependency vulnerabilities with a viable attack path through our code

### What doesn't qualify

- Vulnerabilities in the mock server (`gvm-mock-server`) — it is a testing tool, not production software
- Issues in upstream dependencies without a demonstrated attack path through rust-gvm
- Denial-of-service via malformed GMP XML from a trusted gvmd server (trusted network assumption)

## Security Measures

### Dependency Auditing

- **[cargo-audit](https://github.com/rustsec/rustsec)** runs in CI on every push and weekly via the [Security workflow](.github/workflows/security.yml), checking against the [RustSec Advisory Database](https://rustsec.org/)
- **[cargo-deny](https://github.com/EmbarkStudios/cargo-deny)** enforces license compliance, bans, and source restrictions (see [`deny.toml`](deny.toml))
- **[Dependabot](https://docs.github.com/en/code-security/dependabot)** monitors Cargo, pip, and GitHub Actions dependencies with weekly update PRs ([`.github/dependabot.yml`](.github/dependabot.yml))
- **[cargo-machete](https://github.com/bnjbvr/cargo-machete)** checks for unused dependencies in CI

### Known Advisory Exceptions

Accepted advisories are documented in [`deny.toml`](deny.toml) with rationale:

| Advisory | Crate | Reason |
|----------|-------|--------|
| RUSTSEC-2023-0071 | `rsa` | Transitive via `russh`; Marvin attack requires RSA key exchange — mitigated by preferring Ed25519/ECDSA keys |
| RUSTSEC-2025-0134 | `rustls-pemfile` | Unmaintained; will migrate when `rustls` ecosystem provides replacement |

### Supply Chain

- All dependencies sourced exclusively from [crates.io](https://crates.io)
- Git dependencies denied by default (`[sources] unknown-git = "deny"`)
- GitHub Actions pinned to major version tags; Dependabot keeps them current
- SBOM (CycloneDX) generated on every release and nightly build

### Code Quality

- `cargo clippy` with `-D warnings` in CI
- `#[deny(unsafe_code)]` — no unsafe blocks in any crate
- MSRV tested (currently Rust 1.75.0)
- All XML parsing uses `quick-xml` with default limits (no unbounded expansion)

## Security-Relevant Architecture

### Trust Model

```
┌─────────────┐     GMP/XML      ┌──────────┐
│ rust-gvm    │◄────────────────►│  gvmd    │
│ (client)    │  Unix / SSH / TLS │ (server) │
└─────────────┘                   └──────────┘
       ▲
       │ The transport layer (gvm-connection) handles:
       │ • SSH host key verification
       │ • Unix socket file permissions (OS-level)
       │ • TLS certificate validation (planned)
       │
       │ GMP authentication is username/password over
       │ the encrypted transport — never plaintext TCP.
```

- **gvmd is trusted**: rust-gvm is a client library; it trusts the server's XML responses. Malicious server responses are out of scope (same trust model as python-gvm).
- **Credentials**: Passed at runtime, never stored by the library. Callers are responsible for secure credential management.
- **Transport security**: SSH and TLS transports encrypt all GMP traffic. Unix sockets rely on filesystem permissions.

## GitHub Security Features Checklist

| Feature | Status | Notes |
|---------|--------|-------|
| Private vulnerability reporting | ⬜ **Enable** | Settings → Security → Advisories |
| Dependabot alerts | ✅ Active | Cargo + Actions + pip |
| Dependabot security updates | ⬜ **Enable** | Auto-PRs for vulnerable deps |
| Secret scanning | ⬜ **Enable** | Detects leaked credentials in commits |
| Secret scanning push protection | ⬜ **Enable** | Blocks pushes containing secrets |
| Code scanning (CodeQL) | ⬜ Optional | Limited Rust support; cargo-audit + clippy cover most cases |
| Branch protection | ⬜ **Recommend** | Require PR reviews + status checks on `main` |
| Signed commits | ⬜ Optional | Consider requiring for release tags |
| OSSF Scorecard | ⬜ Deferred | Requires public repo; workflow ready but commented out |

### Recommended Enablement Steps

1. **Private Vulnerability Reporting**: Repository Settings → Code security and analysis → Private vulnerability reporting → Enable
2. **Dependabot Security Updates**: Settings → Code security and analysis → Dependabot security updates → Enable (complements the existing version update PRs with auto-fix PRs for known CVEs)
3. **Secret Scanning + Push Protection**: Settings → Code security and analysis → Secret scanning → Enable both. Free for all repos since GitHub made it available to private repos.
4. **Branch Protection on `main`**:
   - Require pull request reviews (1 reviewer minimum)
   - Require status checks: CI, Security
   - Require linear history (optional, keeps history clean)
   - Restrict who can push directly (admin-only bypass)
5. **OSSF Scorecard**: Uncomment the workflow in `security.yml` when/if the repo goes public

## Changelog

| Date | Change |
|------|--------|
| 2026-03-17 | Initial security policy |
