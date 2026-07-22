# Fuzz Testing for rust-gvm

This directory contains fuzz targets for testing rust-gvm's XML and response parsing.

## Prerequisites

Install `cargo-fuzz`:

```bash
cargo install cargo-fuzz
```

Requires nightly Rust:

```bash
rustup install nightly
```

## Running Fuzz Targets

From the repository root:

```bash
# P0: Fuzz the low-level XML parser
cargo +nightly fuzz run fuzz_xml_parser

# P0: Fuzz the high-level response model parsers
cargo +nightly fuzz run fuzz_response_parser

# P1: Grammar-based fuzzing of parse_document()
cargo +nightly fuzz run fuzz_xml_node_builder

# P1: Chunked streaming reader fuzzing
cargo +nightly fuzz run fuzz_streaming_reader
```

## Fuzz Targets

| Target | Priority | Description |
|--------|----------|-------------|
| `fuzz_xml_parser` | P0 | Tests `gvm-protocol::Response` construction from arbitrary bytes |
| `fuzz_response_parser` | P0 | Tests typed response parsers in `gvm-gmp::responses` |
| `fuzz_xml_node_builder` | P1 | Grammar-based fuzzing of `parse_document()` with structured XML |
| `fuzz_streaming_reader` | P1 | Checks exact frame extraction and single-vs-chunked equivalence for `XmlReader` |

## Corpus

Fuzz corpus is stored in `fuzz/corpus/<target>/`. Seed inputs can be added manually.

## Artifacts

Crash inputs are saved to `fuzz/artifacts/<target>/`. These should be converted to regression tests.

## CI Integration

Fuzzing is not run in CI by default (it's time-unbounded). For CI smoke tests, use:

```bash
cargo +nightly fuzz run fuzz_xml_parser -- -max_total_time=60
```
