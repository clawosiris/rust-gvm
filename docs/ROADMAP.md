# rust-gvm Roadmap and Support Direction

rust-gvm's primary goal is to be a current, typed Rust client and protocol ecosystem for Greenbone Management Protocol (GMP) and Greenbone Vulnerability Manager (gvmd).

Compatibility with python-gvm is important for migration, interoperability, and validation, but rust-gvm should not be limited to python-gvm's public API shape or coverage. When python-gvm and current GMP/GVMD behavior differ, rust-gvm should model the protocol behavior directly and document any migration impact.

## Support Goals

- Track current GMP/GVMD protocol versions and behavior directly.
- Model command and response types from GMP/GVMD semantics.
- Preserve compatibility shims or migration affordances where they help existing python-gvm users.
- Keep the mock server aligned with real gvmd behavior, including errors and ignored or unsupported attributes.
- Add conformance and end-to-end coverage against supported gvmd versions.
- Document supported GMP versions, known gaps, and compatibility expectations.

## Version Support

The current codebase negotiates GMP 22.4 through 22.8+:

- GMP 22.4 maps to the `Gmp224`/`GmpVersioned::V224` client family.
- GMP 22.5 maps to the `Gmp225`/`GmpVersioned::V225` client family.
- GMP 22.6 maps to the `Gmp226`/`GmpVersioned::V226` client family.
- GMP 22.7 maps to the `Gmp227`/`GmpVersioned::V227` client family.
- GMP 22.8 and newer currently map to `GmpNext`/`GmpVersioned::Next`.
- GMP versions older than 22.4 are rejected as unsupported.

This is a code-level support snapshot, not a full conformance guarantee. See
[SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) for the qualified command/version
matrix, public evidence pin, and deterministic schema drift audit. Real gvmd
validation remains a separate follow-up.

## Compatibility Policy

python-gvm compatibility is a secondary target:

- Use python-gvm tests to catch migration and interoperability regressions.
- Keep examples and migration notes clear for python-gvm users.
- Avoid cloning python-gvm's API shape when GMP/GVMD semantics call for a different Rust model.
- Prefer typed Rust options and response models that match the protocol.
- Keep raw `send`/`call` access available for commands or response details that are not yet modeled.

## Coverage Policy

A GMP feature is considered covered when the relevant pieces are aligned:

- Command builders emit the gvmd-supported XML shape.
- Response models parse the gvmd-supported XML shape.
- Version gates reflect the GMP versions where a command is available.
- Mock-server behavior does not mask drift from real gvmd.
- Tests cover serialization, parsing, client flow, and relevant mock-server behavior.
- Docs identify any known limitations or migration differences.

## Deliberate Scope Limits

GMP ticket support is frozen at the currently shipped surface. Existing ticket
command builders, response models, typed-client integration, and mock behavior
remain supported and may receive correctness, security, compatibility,
documentation, and test maintenance. New ticket-specific commands, fields,
helpers, mock behavior, or conformance work are intentionally out of scope.

This is a product-scope decision, not a claim that gvmd lacks additional ticket
behavior. Coverage and schema-drift audits must record newly observed ticket
functionality as an intentional exclusion rather than automatically turning it
into roadmap work. See the canonical
[GMP ticket surface decision](https://github.com/greenbone-hive/rust-gvm-api/blob/main/docs/ticket-surface-scope.md),
recorded from
[`rust-gvm-api` PR #417](https://github.com/greenbone-hive/rust-gvm-api/pull/417).

## Current Tracking

Existing issues:

- [#172](https://github.com/clawosiris/rust-gvm/issues/172) tracks remaining rust-gvm vs gvmd GMP coverage gaps.
- [#247](https://github.com/clawosiris/rust-gvm/issues/247) tracks report option drift where rust-gvm exposes an attribute gvmd ignores.
- [#251](https://github.com/clawosiris/rust-gvm/issues/251) tracks response model drift around user host access and similar XML shape mismatches.
- [#311](https://github.com/clawosiris/rust-gvm/issues/311) tracks generic GMP asset commands alongside typed wrappers.
- [#313](https://github.com/clawosiris/rust-gvm/issues/313) tracks generic GMP config commands alongside scan-config and policy wrappers.

Follow-up issues or milestones should cover:

- Add real gvmd end-to-end or conformance validation for supported versions.
- Document python-gvm migration compatibility expectations and known differences.

## Near-Term Implementation Order

1. Finish the remaining high-value GMP coverage gaps from #172.
2. Fix known protocol drift in command options and response models.
3. Add real gvmd conformance coverage.
4. Expand migration documentation for python-gvm users.
