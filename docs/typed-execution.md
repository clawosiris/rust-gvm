# Typed request/response execution

The `next` Technology Preview lane provides an additive typed execution API.
Each migrated semantic request implements `GmpRequest` and selects exactly one
`GmpResponse` through an associated type:

```rust
use gvm_gmp::commands::targets::{GetTargetsOpts, GetTargetsRequest};

let response = client
    .execute(GetTargetsRequest::new(GetTargetsOpts::default()))
    .await?;
```

No response type annotation or manual `from_response` call is required. Passing
the request to `execute` determines the result type at compile time.

## Compatibility APIs

Existing typed convenience methods remain supported. For migrated commands they
construct the same semantic request and delegate to `execute`:

```rust
let response = client.get_targets(GetTargetsOpts::default()).await?;
```

Existing command builders plus `send` and `call` also remain supported. Use
them for custom XML, commands that have not migrated, or response details not
yet represented by a typed model:

```rust
use gvm_gmp::commands::targets;

let raw = client
    .call(targets::get_targets(GetTargetsOpts::default()))
    .await?;
```

`send` returns any GMP status as a raw response. `call` raises
`GvmError::Server` for a non-2xx status. Typed decoders preserve the existing
typed-facade behavior and report non-2xx statuses through
`GvmError::Parse(ParseError::ServerError { .. })`.

The Phase 1 public contract is owned by `gvm-gmp` (`GmpRequest` and
`GmpResponse`) and `gvm-client` (`GmpClient::execute`). `gvm-client` re-exports
the two traits for ergonomic imports. These names and ownership boundaries are
stable within the additive `next` migration; later phases add command families
without changing this execution shape.

## Custom codecs

Custom and irregular commands have two supported paths. If raw bytes are the
right abstraction, implement `gvm_protocol::Request` (or pass `Vec<u8>`/a byte
slice) and use `send` or `call`. If the command should participate in typed
execution, implement `Request` plus `GmpRequest` on the request type and
`GmpResponse` on its associated response type:

```rust
use gvm_gmp::{GmpRequest, GmpResponse, GmpVersion};
use gvm_gmp::responses::ParseError;
use gvm_protocol::{Request, Response};

struct CustomRequest;

impl Request for CustomRequest {
    fn to_bytes(&self) -> Vec<u8> {
        b"<custom_command/>".to_vec()
    }

    fn semantic_command_name(&self) -> Option<&'static str> {
        Some("custom_command")
    }
}

struct CustomResponse(Response);

impl GmpResponse for CustomResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        let status = response
            .status_code()
            .ok_or_else(|| ParseError::MissingElement("status".into()))?;
        let message = response
            .status_text()
            .ok_or_else(|| ParseError::MissingElement("status_text".into()))?;
        if !(200..300).contains(&status) {
            return Err(ParseError::ServerError { status, message });
        }
        Ok(Self(response.clone()))
    }
}

impl GmpRequest for CustomRequest {
    type Response = CustomResponse;
}
```

Custom response codecs must reject non-2xx statuses as
`ParseError::ServerError` and retain structural field context in other parse
errors. `execute` still applies negotiated-version/help checks to registered
commands and declared semantic aliases, while unknown custom names retain the
raw path's forward compatibility. It also redacts wire bytes before invoking a
trace observer. A semantic alias supplied by `Request::semantic_command_name`
is checked before the XML root command.

## Authoring a migrated command

1. Define a semantic request struct in the owning `gvm-gmp` command module.
2. Validate fallible input in its constructor, reusing the legacy builder's
   validation rather than delaying failures until transport execution.
3. Implement `Request` by delegating to the existing builder so only one XML
   encoding path exists. Preserve `semantic_command_name` metadata when the
   wire root has a different capability name.
4. Implement `GmpRequest` and associate exactly one response model.
5. Implement `GmpResponse` on that existing response model. Use the negotiated
   version only when the response wire shape genuinely differs by version.
6. Convert the existing convenience method into a thin `execute` wrapper; do
   not remove the builder or raw path.
7. Add exact byte-equivalence, response parsing, version/help gating,
   non-success, malformed-response, and redaction tests as applicable.

Irregular commands are first-class. They may retain explicit XML codecs and do
not need Serde derives. A request whose encoding genuinely differs by GMP
version must make that distinction explicit in the GMP layer; transport code is
not the place for command-specific branching.

See [ADR 0001](adr/0001-typed-request-response-execution.md) for ownership,
compatibility, error, and security decisions.
