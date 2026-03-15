# CODEX TASK: Implement gvm-client crate

## Context

Implement `crates/gvm-client` as the high-level async GMP client that combines:
- `gvm-connection` (transport trait)
- `gvm-protocol` (response parsing)
- `gvm-gmp` (typed command builders)

Spec source: `spec/openspec.md` section 3.4.

## Required API

### Core client

```rust
pub struct GmpClient<C: GvmConnection> {
    connection: C,
    version: gvm_gmp::types::GmpVersion,
}

impl<C: GvmConnection> GmpClient<C> {
    pub async fn connect(connection: C) -> Result<Self, GvmError>;
    pub fn version(&self) -> GmpVersion;
    pub async fn send<R: gvm_protocol::Request>(&mut self, request: R) -> Result<gvm_protocol::Response, GvmError>;
    pub async fn call<R: gvm_protocol::Request>(&mut self, request: R) -> Result<gvm_protocol::Response, GvmError>;
    pub async fn disconnect(&mut self) -> Result<(), GvmError>;

    // helper accessors needed by tests and wrappers
    pub fn connection(&self) -> &C;
    pub fn connection_mut(&mut self) -> &mut C;
    pub fn into_inner(self) -> C;
}
```

### Versioned wrappers

Create wrappers and enum:

```rust
pub struct Gmp224<C: GvmConnection>(pub GmpClient<C>);
pub struct Gmp225<C: GvmConnection>(pub GmpClient<C>);
pub struct Gmp226<C: GvmConnection>(pub GmpClient<C>);
pub struct Gmp227<C: GvmConnection>(pub GmpClient<C>);
pub struct GmpNext<C: GvmConnection>(pub GmpClient<C>);

pub enum GmpVersioned<C: GvmConnection> {
    V224(Gmp224<C>),
    V225(Gmp225<C>),
    V226(Gmp226<C>),
    V227(Gmp227<C>),
    Next(GmpNext<C>),
}

impl<C: GvmConnection> GmpVersioned<C> {
    pub async fn connect(connection: C) -> Result<Self, GvmError>;
    pub fn version(&self) -> GmpVersion;
    pub async fn send<R: gvm_protocol::Request>(&mut self, request: R) -> Result<gvm_protocol::Response, GvmError>;
    pub async fn call<R: gvm_protocol::Request>(&mut self, request: R) -> Result<gvm_protocol::Response, GvmError>;
    pub async fn disconnect(&mut self) -> Result<(), GvmError>;
}
```

## Version negotiation behavior

During `connect`:
1. connect transport
2. send `<get_version/>`
3. parse response and extract text from `<version>` (accept `major.minor` formats)
4. map to enum:
   - 22.4 -> V224
   - 22.5 -> V225
   - 22.6 -> V226
   - 22.7 -> V227
   - >22.7 -> Next
   - unsupported major -> `GvmError::UnsupportedVersion`

## Error type

Create `error.rs` with `GvmError` enum (align to spec as much as practical now):
- Connection(String)
- XmlParse(String)
- InvalidState(String)
- Server { status: u16, message: String }
- UnsupportedVersion(u16, u16)
- Timeout(std::time::Duration)
- Io(std::io::Error)

Conversions:
- from `std::io::Error`
- map connection crate errors to `Connection`

`call()` must call `raise_for_status` equivalent:
- parse response status
- if non-2xx, return `GvmError::Server { status, message }`

## Tests (must add)

Create integration tests in `crates/gvm-client/tests/client_integration.rs` behind `#![cfg(feature = "unix-socket-tests")]`:

- connect + negotiate version 22.5 against `gvm-mock-server`
- send authenticate command (`gvm_gmp::commands::authentication::authenticate`) and check success
- send create_target + get_targets and verify success statuses
- server error mapping (e.g., invalid command via raw request) -> `GvmError::Server`
- versioned enum returns `V225` for default mock server
- disconnect works and leaves transport disconnected

Also unit tests for version parsing function in `src/version.rs` or similar.

## Design constraints

- Do NOT rewrite gvm-protocol/gvm-connection APIs.
- Use existing `Response` type from gvm-protocol.
- Keep crate minimal and focused; no large command-specific wrappers yet.
- Preserve `#![forbid(unsafe_code)]` if adding crate attrs.

## Validation

Run:
1. `cargo test -p gvm-client --features unix-socket-tests`
2. `cargo test --workspace`
3. `cargo clippy --workspace --all-targets --all-features`

Fix build/test errors. Warnings are acceptable if caused by existing workspace lint policy.

When done, run:
openclaw system event --text "Done: Implemented gvm-client high-level async client with version negotiation" --mode now
