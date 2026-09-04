# Typed Client Facade Coverage

The public typed facade is the set of inherent `GmpClient` methods implemented
in `crates/gvm-client/src/typed.rs`. Issue #398 called this surface
`GmpClientExt`; the project keeps the existing inherent-method API rather than
introducing a compatibility-only extension trait.

Every current method is classified as **integration covered** in
`crates/gvm-client/tests/typed_facade_inventory.rs`. That inventory also has
explicit (currently empty) **compile only** and **requires integration**
classes. Its test extracts every `pub async fn` from `typed.rs`, rejects
duplicates and unknown entries, and fails when a new helper is not classified.
It additionally requires every integration-covered name to appear as a direct
method call in the client/mock integration suite.

Coverage is organized by behavior family:

- discovery/list and administration helpers use table-driven fixture
  responses and assert typed results plus command history;
- create helpers use a shared response table and assert typed create IDs;
- report export exercises both the simple and options XML shapes;
- generic assets, host and operating-system aliases, and result queries assert
  every typed facade shape plus their shared wire-command inventory;
- generic configuration and port-list coverage exercises all fourteen list,
  detail, lifecycle, and port-range semantic operations;
- report configuration, report format, and TLS certificate coverage exercises
  all 23 existing builder shapes through fixed response associations;
- server-status and malformed-payload cases assert typed error mapping;
- the 22.6 registry gate, 22.8 registry gate, and 22.8 semantic-command gates
  are exercised through typed methods.

The response-model expansion tracked by
[#371](https://github.com/clawosiris/rust-gvm/issues/371),
[#372](https://github.com/clawosiris/rust-gvm/issues/372),
[#373](https://github.com/clawosiris/rust-gvm/issues/373), and
[#374](https://github.com/clawosiris/rust-gvm/issues/374) is not duplicated
here. This inventory covers the public typed methods that exist now; those
issues remain the authority for any further model/API acceptance work.
