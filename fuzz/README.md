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
# Fuzz the low-level XML parser
cargo +nightly fuzz run fuzz_xml_parser

# Fuzz the high-level response model parsers
cargo +nightly fuzz run fuzz_response_parser
```

## Fuzz Targets

| Target | Description |
|--------|-------------|
| `fuzz_xml_parser` | Tests `gvm-protocol::Response` construction from arbitrary bytes |
| `fuzz_response_parser` | Tests typed response parsers in `gvm-gmp::responses` |

## Corpus

Fuzz corpus is stored in `fuzz/corpus/<target>/`. Seed inputs can be added manually.

## Artifacts

Crash inputs are saved to `fuzz/artifacts/<target>/`. These should be converted to regression tests.

## CI Integration

Fuzzing is not run in CI by default (it's time-unbounded). For CI smoke tests, use:

```bash
cargo +nightly fuzz run fuzz_xml_parser -- -max_total_time=60
```
