# Agent Code Map

This is a fast orientation guide for coding agents. It points to ownership boundaries and common edit paths so each task does not start with a repo-wide rediscovery pass.

## First Files

- `README.md`: public positioning, crate overview, quick-start examples.
- `docs/ROADMAP.md`: support direction, compatibility policy, and issue tracking.
- `docs/STATUS.md`: implementation status, version support snapshot, and coverage notes.
- `docs/gvmd-transport-analysis.md`: gvmd transport model and why GMP is handled as XML over persistent sockets.
- `docs/response-models-rfc.md`: response parsing/modeling direction.

## Request Flow

The main client path is:

1. Application code calls `gvm-client`.
2. `gvm-client` negotiates version with `get_version`, checks version gates, and calls typed or raw GMP requests.
3. `gvm-gmp` builds typed GMP XML commands and parses typed response models.
4. `gvm-protocol` serializes commands, parses raw responses, and frames XML messages from byte streams.
5. `gvm-connection` sends and reads bytes over Unix sockets, verified TLS, or SSH tunnels.
6. `gvm-mock-server` can stand in for gvmd in unit/integration tests.

## Crate Ownership

- `crates/gvm-protocol`: XML command builder, raw response parser, `Request` trait, streaming XML completeness detection.
- `crates/gvm-gmp`: GMP domain command builders, protocol enums, shared option types, typed response models.
- `crates/gvm-client`: high-level async API, version negotiation, `GmpVersioned`, version-gated traits, typed convenience methods.
- `crates/gvm-connection`: transport abstraction and concrete Unix/TLS/SSH connections.
- `crates/gvm-mock-server`: programmable mock gvmd with echo, fixture, stateful, scenario, fault, history, and version behavior.

## Common Edit Paths

Adding or changing a GMP command:

- Start in `crates/gvm-gmp/src/commands/<domain>.rs`.
- Add shared enum/type support in `crates/gvm-gmp/src/enums.rs`, `types.rs`, or `common.rs` only when the value is reused.
- Export the module or item through `crates/gvm-gmp/src/commands/mod.rs` or `crates/gvm-gmp/src/lib.rs` when public.
- Add serialization tests in `crates/gvm-gmp/tests/test_<domain>.rs`.
- If exposed by the high-level client, update `crates/gvm-client/src/typed.rs`.
- If version-gated, update `crates/gvm-client/src/version.rs` and any typed version traits in `crates/gvm-client/src/lib.rs`.
- If the mock server should understand it, update `crates/gvm-mock-server/src/handler.rs`, `response_gen.rs`, `store.rs`, or `fixtures.rs` as appropriate.

Changing response parsing:

- Start in `crates/gvm-gmp/src/responses/<domain>.rs`.
- Use shared helpers from `crates/gvm-gmp/src/responses/common.rs` before adding local XML traversal.
- Re-export response types from `crates/gvm-gmp/src/responses/mod.rs`.
- Add parser fixtures/tests near the domain response tests or in the relevant client integration test.
- Check whether mock responses in `crates/gvm-mock-server/src/response_gen.rs` or `fixtures.rs` need to match real gvmd.

Changing client behavior:

- `crates/gvm-client/src/lib.rs`: `GmpClient`, `GmpVersioned`, version-specific wrapper traits, raw `send`/`call`.
- `crates/gvm-client/src/typed.rs`: typed convenience methods that combine command builders with typed response parsing.
- `crates/gvm-client/src/version.rs`: version parsing, mapping, command minimums, command support checks.
- `crates/gvm-client/src/error.rs`: high-level error variants and display behavior.
- Tests live under `crates/gvm-client/tests/`.

Changing transport behavior:

- `crates/gvm-connection/src/connection.rs`: transport trait.
- `crates/gvm-connection/src/unix.rs`: Unix socket transport.
- `crates/gvm-connection/src/ssh.rs`: SSH streamlocal tunnel transport.
- `crates/gvm-connection/src/tls.rs`: verified TLS transport and optional client identity.
- `crates/gvm-connection/src/error.rs`: transport error mapping.
- Tests live under `crates/gvm-connection/tests/`.

Changing mock server behavior:

- `crates/gvm-mock-server/src/handler.rs`: command dispatch and session/auth behavior.
- `crates/gvm-mock-server/src/command_parser.rs`: incoming XML command parsing.
- `crates/gvm-mock-server/src/response_gen.rs`: generated GMP response XML.
- `crates/gvm-mock-server/src/store.rs`: in-memory state and CRUD resources.
- `crates/gvm-mock-server/src/fixtures.rs`: fixture-mode responses.
- `crates/gvm-mock-server/src/fault.rs` and `scenario.rs`: failure injection and scripted playback.
- Tests live under `crates/gvm-mock-server/tests/`.

## Protocol Drift Checklist

When fixing a mismatch with real gvmd, check all of these before calling it done:

- Command XML matches gvmd-supported attributes/elements.
- Response parser accepts the gvmd-supported XML shape.
- Mock server does not simulate behavior gvmd does not have.
- Version gates match the GMP version where the command/field exists.
- Public typed API is not misleading; if compatibility requires keeping an old field, document or deprecate it.
- Tests cover both serialization and parsing when both sides exist.

## Targeted Tests

- Command XML only: `cargo test -p gvm-gmp --test test_<domain>`
- Response model only: `cargo test -p gvm-gmp <response_or_domain_filter>`
- Client typed API: `cargo test -p gvm-client`
- Version gates: `cargo test -p gvm-client version`
- Mock-server command behavior: `cargo test -p gvm-mock-server --test <test_file>`
- Transport behavior: `cargo test -p gvm-connection`
- Python interoperability: `make test-integration`
- Full workspace smoke: `cargo test --workspace`

## Things Not To Rediscover

- GMP is not HTTP. gvmd exposes XML over persistent Unix/TCP/TLS sockets; see `docs/gvmd-transport-analysis.md`.
- `python-gvm` compatibility is useful, but current GMP/GVMD behavior is the source of truth for protocol modeling.
- The mock server is a test tool, not proof that behavior matches gvmd.
- Raw `send`/`call` exists so unsupported or not-yet-modeled GMP details can still be reached without adding premature wrappers.
- `GmpNext` is the forward-compatible bucket for newer supported versions, not a guarantee that every new command is modeled.
