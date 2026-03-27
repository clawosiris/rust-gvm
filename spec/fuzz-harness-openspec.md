# OpenSpec: Fuzz Harness Design for rust-gvm

## 1. Overview

This document specifies the fuzzing strategy, harness implementations, and coverage targets for rust-gvm's security-critical parsing surfaces.

### Goals

- **Find crash bugs** in XML and response parsing before they reach production
- **Ensure graceful handling** of malformed/malicious input
- **Establish regression testing** from discovered issues
- **Enable continuous fuzzing** via OSS-Fuzz integration (future)

### Non-Goals

- Performance benchmarking (use criterion instead)
- Protocol correctness validation (use E2E tests)
- Network-level fuzzing (out of scope for this library)

## 2. Attack Surface Analysis

### Primary Targets

| Component | Risk | Priority | Rationale |
|-----------|------|----------|-----------|
| `gvm-protocol::Response` | HIGH | P0 | Parses raw XML from untrusted gvmd server |
| `responses::common::XmlNode` | HIGH | P0 | Hand-rolled tree builder; OOM/panic risks |
| All `*Response::from_response()` | MEDIUM | P1 | Type conversion from parsed XML |
| `gvm-protocol::XmlReader` | MEDIUM | P1 | Streaming XML parser wrapper |

### Secondary Targets (lower priority)

| Component | Risk | Priority | Rationale |
|-----------|------|----------|-----------|
| Command builders | LOW | P2 | Output-only; no untrusted input |
| Connection handling | LOW | P2 | Uses well-tested libraries (tokio, russh) |

## 3. Harness Specifications

### 3.1 `fuzz_xml_parser` (P0)

**Target**: `gvm_protocol::Response::from()`

**Input**: Arbitrary byte sequences interpreted as UTF-8

**Coverage goals**:
- Empty input
- Truncated XML
- Deeply nested elements (stack exhaustion)
- Very long attribute values (memory exhaustion)
- Invalid UTF-8 sequences (should reject cleanly)
- XML bombs (entity expansion attacks)
- Null bytes and control characters

**Expected behavior**: Never panic. Return errors for invalid input.

```rust
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let response = gvm_protocol::Response::from(s);
        let _ = response.data();
        let _ = response.status();
        let _ = response.status_text();
    }
});
```

### 3.2 `fuzz_response_parser` (P0)

**Target**: All `*Response::from_response()` implementations

**Input**: Arbitrary byte sequences wrapped in `Response`

**Coverage goals**:
- Missing required elements
- Wrong element types (string where int expected)
- Extra/unknown elements (should ignore)
- Empty collections
- Extremely large collections (memory limits)
- Unicode edge cases in string fields
- Integer overflow in numeric fields

**Expected behavior**: Return `Err(ParseError)` for invalid input. Never panic.

```rust
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let response = gvm_protocol::Response::from(s);
        // Try all response types
        let _ = GetVersionResponse::from_response(&response);
        let _ = GetTargetsResponse::from_response(&response);
        let _ = GetTasksResponse::from_response(&response);
        // ... etc
    }
});
```

### 3.3 `fuzz_xml_node_builder` (P1 — to implement)

**Target**: `responses::common::parse_document()`

**Input**: Well-formed XML strings (use grammar-based generation)

**Coverage goals**:
- Attribute parsing edge cases
- Child element ordering
- Mixed content (text + elements)
- Namespace handling (if applicable)
- CDATA sections
- Comments and processing instructions

**Implementation approach**:
```rust
#[derive(Arbitrary)]
struct XmlInput {
    root_name: AsciiString,
    attributes: Vec<(AsciiString, AsciiString)>,
    children: Vec<XmlChild>,
}

fuzz_target!(|input: XmlInput| {
    let xml = input.to_xml_string();
    let _ = parse_document(&xml);
});
```

### 3.4 `fuzz_streaming_reader` (P1 — to implement)

**Target**: `gvm_protocol::XmlReader`

**Input**: Chunked XML data simulating network reads

**Coverage goals**:
- Mid-element chunk boundaries
- Mid-attribute chunk boundaries
- Very small chunks (1 byte)
- Very large chunks
- Interleaved complete/incomplete elements

## 4. Seed Corpus Strategy

### Initial Seeds

Create seed corpus from:

1. **Real GMP responses** (sanitized) from E2E test fixtures
2. **Edge case examples** from GMP protocol documentation
3. **Minimal valid responses** for each response type
4. **Known-problematic patterns** from past bugs

### Corpus Location

```
fuzz/corpus/fuzz_xml_parser/
fuzz/corpus/fuzz_response_parser/
fuzz/corpus/fuzz_xml_node_builder/
fuzz/corpus/fuzz_streaming_reader/
```

### Seed Generation Script

```bash
#!/bin/bash
# scripts/generate_fuzz_seeds.sh

CORPUS_DIR="fuzz/corpus"

# Extract XML from test fixtures
for fixture in crates/gvm-gmp/src/responses/**/tests/*.xml; do
    target=$(basename $(dirname $(dirname $fixture)))
    mkdir -p "$CORPUS_DIR/fuzz_response_parser"
    cp "$fixture" "$CORPUS_DIR/fuzz_response_parser/$(basename $fixture)"
done

# Generate minimal valid responses
cat > "$CORPUS_DIR/fuzz_xml_parser/minimal_ok" << 'XML'
<response status="200" status_text="OK"/>
XML

cat > "$CORPUS_DIR/fuzz_xml_parser/minimal_error" << 'XML'
<response status="400" status_text="Bad request"/>
XML
```

## 5. CI Integration

### Local Development

```bash
# Quick smoke test (60 seconds)
cargo +nightly fuzz run fuzz_xml_parser -- -max_total_time=60

# Full run (until stopped or crash)
cargo +nightly fuzz run fuzz_xml_parser
```

### CI Smoke Test (optional)

Add to `security.yml` for time-bounded CI runs:

```yaml
fuzz-smoke:
  name: Fuzz Smoke Test
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v6
    - uses: dtolnay/rust-toolchain@nightly
    - name: Install cargo-fuzz
      run: cargo install cargo-fuzz
    - name: Run fuzz smoke test
      run: |
        cargo +nightly fuzz run fuzz_xml_parser -- -max_total_time=120
        cargo +nightly fuzz run fuzz_response_parser -- -max_total_time=120
```

### OSS-Fuzz Integration (future)

For continuous fuzzing, integrate with Google OSS-Fuzz:

1. Create `projects/rust-gvm/` in oss-fuzz repo
2. Add `Dockerfile`, `build.sh`, `project.yaml`
3. Submit PR to oss-fuzz

## 6. Crash Handling

### Artifact Location

Crashes are saved to `fuzz/artifacts/<target>/crash-<hash>`.

### Triage Process

1. Minimize crash input: `cargo +nightly fuzz tmin <target> <artifact>`
2. Analyze root cause
3. Add minimized input as regression test in `crates/*/tests/`
4. Fix the bug
5. Verify fix: `cargo +nightly fuzz run <target> <minimized_input>`

### Regression Test Template

```rust
#[test]
fn regression_fuzz_crash_001() {
    // Minimized crash input from fuzz/artifacts/fuzz_xml_parser/crash-abc123
    let input = include_bytes!("fixtures/fuzz_crash_001.xml");
    let s = std::str::from_utf8(input).unwrap();
    let response = gvm_protocol::Response::from(s);
    // Should not panic
    let _ = response.status();
}
```

## 7. Implementation Phases

### Phase 1: Infrastructure (this PR)
- [x] `fuzz/Cargo.toml` setup
- [x] Basic `fuzz_xml_parser` target
- [x] Basic `fuzz_response_parser` target
- [x] README with usage instructions

### Phase 2: Seed Corpus
- [ ] Extract seeds from existing test fixtures
- [ ] Create minimal valid response seeds
- [ ] Add edge case seeds from GMP docs

### Phase 3: Enhanced Harnesses
- [x] Implement `fuzz_xml_node_builder` with grammar-based generation
- [x] Implement `fuzz_streaming_reader` for chunked input
- [ ] Add coverage instrumentation analysis

### Phase 4: CI Integration
- [ ] Add optional fuzz smoke test to security workflow
- [ ] Set up artifact upload for crash inputs
- [ ] Document triage process

### Phase 5: OSS-Fuzz (optional)
- [ ] Prepare oss-fuzz project files
- [ ] Submit integration PR
- [ ] Monitor continuous fuzzing results

## 8. Success Criteria

- [ ] All P0 harnesses implemented and runnable
- [ ] No crashes found after 24h of local fuzzing
- [ ] Seed corpus covers all response types
- [ ] Regression tests added for any discovered crashes
- [ ] CI smoke test passing (if enabled)

## 9. References

- [cargo-fuzz book](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [OSS-Fuzz Rust guide](https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/)
- [Arbitrary crate](https://docs.rs/arbitrary/latest/arbitrary/)
