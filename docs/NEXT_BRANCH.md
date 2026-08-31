# `next` Development Branch

The long-lived `next` branch is the integration lane for
[issue #523](https://github.com/greenbone-hive/rust-gvm/issues/523) and related
forward-looking API work that needs to mature independently from `main`.

## Branch roles

- `main` remains the release integration branch.
- `next` carries additive Technology Preview work whose public APIs may change
  while the design is proven family by family.
- Short-lived implementation branches target `next` through pull requests.
- Unrelated fixes and release work continue to target `main`.

## Integration rules

- Keep `next` protected and require the independent `CI` and `Security` gates.
- Rebase short-lived branches onto the latest `next` before pushing them for
  review; do not rewrite the shared `next` branch.
- Bring applicable `main` changes into `next` through a reviewed synchronization
  pull request so history and validation remain visible.
- Move work from `next` to `main` only through bounded, reviewed pull requests;
  do not merge the whole development branch as a release shortcut.

The paired `greenbone-hive/rust-gvm-api` `next` branch consumes this branch with
a branch-qualified Cargo dependency and an exact lockfile revision. Downstream
lockfile refreshes are explicit integration events and run that repository's
own CI, Security, and branch-specific E2E gates.
