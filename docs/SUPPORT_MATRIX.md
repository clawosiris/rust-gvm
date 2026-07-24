# GMP and gvmd Support Matrix

This document describes what rust-gvm's code can negotiate and exercise. It is
not a claim of full conformance with every gvmd deployment or feature build.

## Version routing

| Negotiated GMP version | Typed client family | Registry entries permitted | Mock version |
|---|---|---:|---|
| 22.4 | `Gmp224` | 115 | `V22_4` |
| 22.5 | `Gmp225` | 115 | `V22_5` |
| 22.6 | `Gmp226` | 120 | `V22_6` |
| 22.7 | `Gmp227` | 120 | `V22_7` |
| 22.8 and newer | `GmpNext` | 155 | `V22_8` |

The command count is derived from
`gvm_gmp::capabilities::COMMAND_CAPABILITIES`. Five commands require GMP 22.6
and another 35 require GMP 22.8. It describes typed-client gates and stateful
mock behavior, not the commands enabled in every gvmd build. The client
deliberately permits unknown raw commands for forward compatibility; standard
mock responses reject commands absent from the registry. Explicit fixture and
scenario configuration remains programmable by design.

`get_scan_report` follows the public python-gvm `GMPNext` placement and is
therefore gated at 22.8. Current gvmd source compiles the command
unconditionally even in builds that may still advertise 22.7, so applications
using such a deployment can send the public builder through a lower-level
connection path, but the versioned high-level client will reject it until the
server advertises 22.8.

## Command and mock qualification

The registry contains 155 wire command names:

| Qualification | Count | Meaning |
|---|---:|---|
| Stateful mock behavior | 138 | Bespoke behavior or deterministic generic CRUD |
| Fixture mock behavior | 10 | Deterministic built-in fixture response |
| Echo-only mock behavior | 7 | Intentionally limited to a generic success response |
| Current pinned `GMP.xml.in` | 152 | Present in the public schema snapshot |
| Public gvmd source only | 2 | Implemented publicly but omitted from that schema |
| Legacy compatibility | 1 | Retained for public legacy-client compatibility |

Mock support is test support, not proof of real-gvmd conformance. In particular,
generic CRUD does not imply that every field and side effect matches gvmd.

The three commands outside the pinned schema are explicitly qualified:

- `modify_credential_store` is feature-gated and implemented in current public
  gvmd source, but is absent from the pinned `GMP.xml.in`.
- `verify_credential_store` is likewise feature-gated and implemented in the
  public credential-store source while absent from the pinned schema.
- `delete_tls_certificate` is retained for compatibility with the public
  python-gvm GMP 22.4 API. It is absent from the pinned current gvmd schema and
  implementation, so applications must not infer current-gvmd support from the
  builder alone.

## Pinned public evidence and drift audit

The deterministic snapshot is extracted from Greenbone's public gvmd commit
[`fb21137097f41e5eb83bb45ee43170b775dbea49`](https://github.com/greenbone/gvmd/commit/fb21137097f41e5eb83bb45ee43170b775dbea49),
file
[`src/schema_formats/XML/GMP.xml.in`](https://github.com/greenbone/gvmd/blob/fb21137097f41e5eb83bb45ee43170b775dbea49/src/schema_formats/XML/GMP.xml.in).
The snapshot records the source file SHA-256 and its 152 unique top-level
commands. The source-only qualification is backed by the same commit's
[credential-store implementation](https://github.com/greenbone/gvmd/blob/fb21137097f41e5eb83bb45ee43170b775dbea49/src/gmp_credential_stores.c).
The legacy qualification is backed by public python-gvm commit
[`2bb100fd03f02e598f046e2032e12550b5b14751`](https://github.com/greenbone/python-gvm/blob/2bb100fd03f02e598f046e2032e12550b5b14751/gvm/protocols/gmp/requests/v224/_tls_certificates.py).

To audit another public `GMP.xml.in` checkout:

```console
cargo run -p gvm-gmp --example audit_gmp_schema -- /path/to/GMP.xml.in
```

The command exits unsuccessfully and lists schema-only or registry-only names
when the public schema has drifted. Updating the pin requires reviewing those
differences and their version/evidence qualifications; replacing the snapshot
alone is insufficient.

## Validation boundary

The support claim covers deterministic serialization/parsing tests, shared
client/mock version gates, transport-level mock interoperability, and the
pinned public schema audit. It does not yet include a release-by-release
real-gvmd conformance suite. That gap should remain explicit until such a suite
is available.
