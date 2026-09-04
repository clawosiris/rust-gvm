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

## Specialized task variants

Task variants that share an XML root still use distinct semantic Rust values.
For example, standard scans, imports, agent-group scans, OCI/container-image
scans, web-application scans, and audits all reuse `<create_task>`, but each has
a request type whose fields match that operation. Compatibility aliases such as
container/import and container-image/OCI remain separately named while
delegating to the same established builders.

Agent-group, OCI/container-image, and web-application task requests declare
their GMP Next semantic capability even though the wire root is the baseline
`create_task` command. Generic execution therefore rejects them before sending
on GMP 22.7 and earlier, preserving the existing versioned-client boundary.
The client also recognizes these shapes when their existing raw builders are
passed to `send` or `call`, so the compatibility escape hatch cannot bypass the
same gate. Import/container and move requests retain their established baseline
behavior.

## Agents and integration configurations

All agent, agent-group, and integration-configuration commands require GMP
22.8. Their semantic requests delegate to the existing builders, so filters,
identifier collections, scheduler values, nested agent defaults, and complete
integration replacements remain byte-for-byte compatible. The typed agent and
agent-group facade methods and the parsed integration helpers now use
`execute`; the raw integration methods remain available for callers that need
the unmodeled response.

Agent installer instructions retain their language and origin metadata.
Support-bundle responses continue to decode base64 content into binary bytes
and validate declared sizes. OIDC client secrets remain redacted from
semantic-request diagnostics and wire tracing.

Audit list, detail, create, clone, modify, delete, start, stop, and resume
requests likewise remain audit-scoped types even where their wire command is a
task command. This keeps compile-time intent explicit without duplicating XML
encoding or changing server behavior. Fallible audit modification validates
observer updates in its constructor before execution.

## Credential stores and semantic aliases

Credential stores are available from GMP 22.8. Their list, detail,
verification, and preference-bearing modification requests use dedicated wire
roots. Store-backed credentials instead reuse `create_credential` and
`modify_credential`, so their semantic request values explicitly identify the
newer operation before sending:

```rust
use gvm_gmp::commands::credentials::{
    CreateCredentialStoreCredentialRequest, CredentialStoreCredentialOpts,
};
use gvm_gmp::CredentialStoreCredentialType;

let credential = client
    .execute(CreateCredentialStoreCredentialRequest::new(
        "production vault credential",
        CredentialStoreCredentialType::UsernamePassword,
        "vault-entry-1",
        "host-1",
        CredentialStoreCredentialOpts::default(),
    ))
    .await?;
```

This preserves the `create_credential_store_credential` and
`modify_credential_store_credential` capability gates even though those names
do not appear as XML roots. A client negotiated below GMP 22.8 rejects them
before transport. Existing builders remain authoritative for vault and host
fields, store preferences keep the existing wire-trace redaction, and the
preference-bearing semantic request deliberately provides no `Debug`
representation that could expose its values.

## Alert and schedule command shapes

Semantic requests model every public alert and schedule operation even when
multiple operations reuse one XML root. Alert list/detail and create/clone pairs
therefore remain distinct Rust request types with their established shared
response models. Alert triggering is also explicit: it emits the existing
`<get_reports alert_id="..." report_id="...">` shape and associates that
request with `GetReportsResponse`, while `test_alert` uses the ordinary action
response codec.

Schedule requests retain both input levels. `CreateScheduleRequest` and
`ModifyScheduleRequest` accept the raw iCalendar compatibility options;
`CreateTypedScheduleRequest` and `ModifyTypedScheduleRequest` accept validated
first-run and recurrence input and delegate to the existing typed builders.
Typed convenience methods for both forms use `execute`, so status handling,
parse context, version checks, and redacted tracing remain identical.

## Supporting resource lifecycles and trashcan recovery

Filters and tags each expose semantic list, detailed-get, create, clone,
modify, and delete request values. The list/detail and create/clone pairs keep
separate Rust types even where they share a wire command and response model,
so call-site intent remains explicit while the established builders remain the
single XML encoders.

Notes and overrides follow the same lifecycle pattern. Their semantic request
values delegate to the existing builders, preserving NVT associations, optional
task/result fields, omit/replace/clear host updates, severity fields, and
ultimate deletion. Retained facade helpers—including the newly completed
detail, clone, modify, and delete methods—execute through the same generic
client path without changing raw compatibility.

Trashcan operations follow the same rule. `EmptyTrashcanRequest` selects the
existing empty-trashcan response, while `RestoreRequest` and
`RestoreFromTrashcanRequest` preserve the two public builder names as distinct
semantic values over the same byte-identical `<restore>` command and typed
response. All of these baseline commands remain available on every supported
GMP version, and retained facade helpers delegate through `execute` without
changing raw `send` or `call` behavior.

## Identity and authorization lifecycles

Users, groups, roles, and permissions each expose semantic list, detailed-get,
create, clone, modify, and delete request values. The list/detail and
create/clone pairs remain separate Rust types despite sharing XML roots and
response models, making the caller's intent explicit without introducing a
second wire encoder.

All 24 requests delegate to the established builders. This preserves the full
user authentication and host-access shape, including explicit role clearing,
as well as group membership, role membership, and permission subject/resource
relationships. User option debug output redacts password values. The
corresponding `GmpClient` convenience methods now use `execute`; existing
builders, response types, `send`, and `call` remain source-compatible.

## NVT and SecInfo queries

All seven NVT builders have matching semantic requests for global and
scan-config-scoped list/detail retrieval, NVT preference list/detail retrieval,
and family discovery. Requests continue to delegate to the public builders, so
filters, preference flags, scan-config identifiers, sorting, and exact XML
bytes remain unchanged. NVT preferences reuse the established
`GetScanConfigPreferencesResponse` codec because gvmd returns the same
`get_preferences_response` shape.

The twelve SecInfo builders retain separate semantic Rust values even though
they all encode `get_info`. Specialized CPE, CVE, CERT-Bund, DFN-CERT,
operating-system, and vulnerability requests keep their existing response
models. `GetInfoRequest` and `GetInfoListRequest` instead select
`GetInfoResponse`, which provides one typed compatibility model across all
public `GenericInfoType` variants, including NVT and OVAL definitions.

Existing CPE, CVE, and advisory facade names remain source-compatible. The
SecInfo operating-system and vulnerability facades are named
`get_secinfo_operating_systems` and `get_secinfo_vulnerabilities` so they do not
change the distinct `get_assets` and legacy `get_vulns` helper behavior. Raw
builders and `send`/`call` remain available for callers that need complete XML.

## Assets, hosts, operating-system assets, and results

Generic asset list/detail/create/modify/delete operations have semantic request
values associated with their existing asset response models. Host and
operating-system asset operations keep separate semantic request types even
though they reuse the generic asset wire roots. This makes resource intent
explicit without duplicating the established encoders or conflating asset
operating systems with the distinct SecInfo `get_info` surface.

The aliases preserve their current behavior: host and operating-system queries
set the same asset `type` values and detail flags; host and generic asset
modification continue to ignore their compatibility `value` fields; and asset
deletion continues to omit the unsupported `ultimate` attribute. Existing
generic and resource-specific facade methods, including detail/modify/delete
completion for the alias families, delegate to `execute`.

Result list and detail requests are likewise distinct semantic values over the
same `get_results` builder family and share `GetResultsResponse`. Filters,
saved-filter identifiers, detail selection, response status mapping, and parse
context remain unchanged. Raw builders and custom execution stay available for
all four families.

## Alternate target lifecycles

The target command boundary includes a semantic `CloneTargetRequest` for the
remaining standard target clone operation and complete list, detail, create,
clone, modify, and delete request types for both OCI-image and web-application
targets. Each request delegates to its existing builder, so filters, saved
filter identifiers, trash and task flags, image/URL collections, credential
relationships, ultimate deletion, and exact XML bytes remain unchanged.

Standard target cloning retains the baseline `create_target` capability. The
OCI-image and web-application request types keep their separate semantic intent
and their existing GMP 22.8 command gates, including clone requests encoded by
the respective creation command. All existing `_parsed` convenience methods
for the two alternate-target families are thin `execute` wrappers. Raw builders
and `send`/`call` remain available without introducing a second encoding path.

## Generic configurations and port lists

Generic configurations retain separate list, detail, create, clone, modify,
and delete request values over the existing generic config builders. Port
lists follow the same lifecycle and include semantic create/delete port-range
requests. The associated response is fixed for every operation, including the
action-shaped port-range responses. Existing filters, usage types, pagination,
identifiers, and mutation options are passed unchanged to the legacy encoders;
raw builders and execution remain supported.

## Report configurations, report formats, and TLS certificates

Report configurations retain distinct semantic values for default and
option-bearing create, list, and delete builders alongside clone, detail, and
modify operations. Report-format create, clone, import, list, detail, modify,
delete, and verify requests preserve import validation and existing response
shapes. TLS certificates expose the same complete lifecycle without changing
certificate or private-key payload encoding. All semantic requests delegate to
the established builders, and raw compatibility APIs remain available.

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
