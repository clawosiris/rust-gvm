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

## Irregular report codecs and version policy

The Phase 3 report family demonstrates that `GmpResponse` is a codec contract,
not a Serde constraint. Report list/detail responses, structured scan and audit
reports, report drill-downs, and both export styles all use `execute` while
retaining their existing explicit parsers:

```rust
use gvm_gmp::commands::reports::{
    GetReportExportOpts, GetReportExportRequest, GetReportVulnsRequest,
};

let export = client
    .execute(GetReportExportRequest::new(
        report_id.clone(),
        GetReportExportOpts::new(report_format_id),
    ))
    .await?;

let vulnerabilities = client
    .execute(GetReportVulnsRequest::new(report_id, Default::default()))
    .await?;
```

`ReportExport` accepts base64-encoded arbitrary bytes and the nested XML export
shape. Structured report parsers retain mixed/repeated element handling and
large responses remain subject to the same bounded transport frame limit as raw
execution. No report parser requires `DeserializeOwned`, and the entire response
is still returned as the request's associated type.

Report command availability is intentionally not inferred from the XML root
alone:

- structured audit reports and audit-report hosts require GMP 22.7;
- structured scan reports, report drill-downs, and synchronous report-format
  export require GMP 22.8;
- synchronous export uses `<get_reports ...>` on the wire but declares the
  semantic capability `get_report_export`;
- asynchronous `export_scan_report` was added without a distinct GMP version
  and therefore continues to require positive XML-help discovery.

These checks run before transmission through the same `send` path used by raw
and ordinary typed requests. The retained raw builders and helpers remain
available when callers need unmodeled report details.

## Scan configurations, policies, and preferences

Scan configurations and policies demonstrate semantic typed requests layered
over shared generic wire commands. Their requests continue to delegate to the
existing `get_configs`, `create_config`, `modify_config`, and `delete_config`
builders, so usage-type scoping, import XML validation, preference base64
encoding, selection ordering, and exact bytes remain unchanged:

```rust
use gvm_gmp::commands::scan_configs::{
    GetScanConfigPreferencesOpts, GetScanConfigPreferencesRequest,
    ModifyScanConfigSetNvtPreferenceRequest,
};

let preferences = client
    .execute(GetScanConfigPreferencesRequest::new(
        GetScanConfigPreferencesOpts {
            config_id: Some(config_id.clone()),
            ..Default::default()
        },
    ))
    .await?;

client
    .execute(ModifyScanConfigSetNvtPreferenceRequest::new(
        config_id,
        "Network connection timeout :",
        "1.3.6.1.4.1.25623.1.0.10330",
        Some("30".into()),
    ))
    .await?;
```

`GetScanConfigPreferencesResponse` preserves both GMP response shapes: default
preferences encode the NVT/type in the preference name, while config-scoped
preferences expose separate NVT metadata, identifier, type, configured value,
alternate values, and default value. Empty values remain distinguishable from
missing values. Passing `None` to a preference-mutation request retains the
existing delete/fallback encoding. Import request constructors validate their
XML before they can be executed, and `SyncConfigRequest` remains global and
parameterless.

See [ADR 0001](adr/0001-typed-request-response-execution.md) for ownership,
compatibility, error, and security decisions.
