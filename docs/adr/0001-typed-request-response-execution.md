# ADR 0001: Typed request/response execution

- Status: Accepted for the `next` Technology Preview lane
- Date: 2026-08-31
- Tracking issue: [#523](https://github.com/greenbone-hive/rust-gvm/issues/523)

## Context

`rust-gvm` already separates transports, raw XML framing, GMP command builders,
and typed response models. The high-level client previously reconnected a
builder and its parser in command-specific methods, while raw callers could pair
a request with the wrong response parser. Replacing hundreds of builders in one
change would create unnecessary compatibility and review risk.

The first production slice must prove one generic contract across version
negotiation, authentication, target list/get/create/modify/delete, and the
irregular asynchronous scan-report export command. Existing builders, raw
requests, convenience methods, transports, mock behavior, redaction, and error
semantics must remain available.

## Decision

### Ownership

- `gvm-protocol` retains only transport-independent raw `Request`, `Response`,
  XML construction, parsing, and framing.
- `gvm-gmp` owns semantic request structs, typed response models,
  `GmpRequest`, and `GmpResponse` because those contracts name GMP resources and
  commands.
- `gvm-client` owns negotiated-version and help-discovery checks, transport,
  tracing, and `GmpClient::execute` / `GmpVersioned::execute`.

### Request encoding

`GmpRequest` extends the existing `gvm_protocol::Request` contract and has one
associated `GmpResponse`. Semantic request structs implement `Request` by
delegating to the existing command builders. The builders therefore remain the
single wire-encoding implementation and the compatibility oracle during the
incremental migration.

Validation that can fail occurs in semantic request constructors, just as it
does in the existing fallible builders. The representative slice has no
version-dependent request bytes. The client still checks the encoded semantic
command against the negotiated version and help-discovery state before sending.
When a later family needs different bytes for different GMP versions, it must
use distinct semantic request types or introduce a reviewed internal codec
extension; it must not hide version branching in transport code.

### Response decoding and errors

`GmpResponse::decode` receives both the raw `Response` and negotiated
`GmpVersion`. Version-independent models delegate to their existing
`from_response` parser. This leaves room for explicitly version-dependent
response shapes without moving protocol semantics into the client.

`execute` intentionally follows the existing typed-facade path: it calls
`send`, then invokes the associated response decoder. It does not call `call`.
Consequently, non-2xx statuses continue to become
`GvmError::Parse(ParseError::ServerError { .. })` for typed methods, while raw
`call` continues to return `GvmError::Server`. Parse-error context and public
error behavior remain compatible.

Version negotiation is the bootstrap exception. `GmpClient::connect` sends a
`GetVersionRequest`, but parses and validates the advertised version before a
negotiated `GmpVersion` exists. Later explicit `get_version` calls use
`execute` normally.

### Compatibility and security

- Existing command-builder functions and typed convenience methods remain
  public. Converted convenience methods are thin wrappers over semantic request
  construction and `execute`.
- `send` and `call` remain the raw/custom escape hatch for commands that have
  not migrated or require caller-owned XML.
- `execute` reuses `send`, preserving version/help gates and redacted wire
  tracing before bytes reach observers.
- `AuthenticateRequest` has a custom redacted `Debug` implementation; request
  bytes still pass through the existing structural wire redactor.
- Asynchronous report export uses the same typed contract but retains its
  positive XML-help-discovery requirement.

## Consequences

The compiler now selects the response from the request type, and callers cannot
ask `execute` to decode an unrelated response. New families can migrate without
removing their old builders or changing downstream behavior. There is temporary
duplication between semantic request structs and builder function signatures,
but no duplicated XML encoder.

This ADR does not authorize a repository-wide conversion or removal of old
APIs. Trait naming and details remain Technology Preview until more standard and
version-irregular families have exercised the contract.

## Validation

- Compile-fail documentation proves `GetVersionRequest` cannot satisfy a
  request bound associated with `AuthenticateResponse`.
- Exact-byte tests compare every representative semantic request with its
  existing builder, including target validation and asynchronous report export.
- Client integration tests exercise `execute`, compatibility wrappers,
  non-success and malformed responses, command-version/help gates, and wire
  redaction.
- Workspace formatting, tests, strict Clippy, documentation, and additive API
  checks remain required before merge.
