# Coverage Policy

Rust workspace line coverage is a protected CI gate, not an upload-only
metric. The floor is **94.00%**, derived by rounding down the **94.93%**
combined Rust/Python Codecov baseline measured on `devel` at commit
`5b7636456821b1039d68c4a044fc5f750fc028ec`. A local Rust-only run on that
tree measures **94.09%** (21,188 of 22,519 lines). The floor therefore remains
below both observed baselines while blocking a whole-percentage-point
regression.

The single source of truth is `.config/coverage.env`. Run the same gate
locally with:

```bash
make coverage-lcov
```

The command writes `lcov.info` and `rust-coverage-summary.json`.
`cargo llvm-cov --fail-under-lines` is authoritative: the coverage job, and
therefore the protected aggregate `CI` job, fails below the floor even if
Codecov is unavailable. CI publishes the LCOV report, Rust JSON summary, and
Python coverage XML as the `coverage-reports` Actions artifact for diagnosis.

Codecov separately requires 90% patch coverage for changed production Rust
lines under `crates/**/src/**/*.rs`. This tolerance permits a narrow amount of
defensive/error-path code while requiring new behavior to be exercised.

Exclusions are deliberately path-based and non-production:

- `target/**` is generated build output.
- `crates/**/tests/**`, `tests/**`, and `crates/**/examples/**` are test or
  example harnesses, which cargo-llvm-cov already omits from production
  coverage.

No production platform module is excluded. Linux/Unix, TLS, and SSH source
compiled by the protected Ubuntu job remains part of both project and patch
coverage. A future generated or platform-only production exclusion requires a
documented, path-specific policy change; broad filename or crate exclusions
are not acceptable.

Run `make coverage-policy-test` to exercise the controlled threshold
regression check. It proves that a value equal to the floor passes and a value
just below it fails.
