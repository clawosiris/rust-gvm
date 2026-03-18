# Large-Response Generator for gvm-mock-server — OpenSpec

**Issue**: #24  
**Status**: Draft  
**Date**: 2026-03-17

---

## 1. Overview

### Problem
Real gvmd instances scanning many systems produce very large GMP responses — `get_reports` responses can exceed 100MB of XML containing thousands of `<result>` elements. Current mock-server tests use small response payloads and do not exercise:
- `XmlReader` incremental parsing under large payloads
- Transport read-loop buffer management
- Client-side memory behavior with large responses
- Response parsing performance

### Goal
Add a deterministic way to generate large but valid GMP report responses in `gvm-mock-server`, and add integration tests that validate rust-gvm handles them correctly.

### Non-goals
- Streaming/chunked response delivery (future, related to #4)
- Benchmarking framework (future)
- Realistic NVT content (deterministic stubs are sufficient)

---

## 2. Architecture

### 2.1 Trigger Mechanism

**Option chosen: Builder config + special report**

The mock server builder gains a configuration option that controls large-report generation. When a report is requested and the large-report config is active, the handler generates a response with N synthetic `<result>` entries.

```rust
MockGmpServer::builder()
    .mode(ServerMode::Stateful)
    .credentials("admin", "admin")
    .large_report(LargeReportConfig {
        result_count: 10_000,
        result_payload_bytes: 1024,  // per-result filler size
    })
    .unix_socket_auto()
    .build()
    .await?;
```

When a task is started and a report is created, `get_reports report_id=<id>` returns a generated report with the configured number of results.

### 2.2 Alternative Considered: Magic report_id

Using a reserved `report_id` (e.g., `"__large__"`) was considered but rejected because:
- It bypasses normal CRUD flow (no create_task → start_task → get_report lifecycle)
- It doesn't integrate with the Stateful mode's resource store
- The builder config approach is more flexible and composable

---

## 3. Response Generation

### 3.1 Generated Report Structure

```xml
<get_reports_response status="200" status_text="OK">
  <report id="<uuid>" format_id="..." content_type="text/xml">
    <report id="<uuid>">
      <results max="{N}" start="1">
        <result id="<uuid-1>">
          <host>10.0.0.1</host>
          <port>443/tcp</port>
          <nvt oid="1.3.6.1.4.1.25623.1.0.{i}">
            <name>Test NVT {i}</name>
            <type>nvt</type>
          </nvt>
          <severity>5.0</severity>
          <threat>Medium</threat>
          <description>{deterministic filler text, configurable size}</description>
        </result>
        <!-- ... repeated N times ... -->
      </results>
      <result_count>
        <full>{N}</full>
        <filtered>{N}</filtered>
      </result_count>
    </report>
  </report>
</get_reports_response>
```

### 3.2 Deterministic Generation

All generated data must be deterministic (same config → same output):
- Result UUIDs: derived from report UUID + index (e.g., `Uuid::new_v5(report_uuid, &i.to_le_bytes())`)
- Host IPs: `10.0.0.{(i % 254) + 1}`
- Ports: cycle through `[22, 80, 443, 8080, 8443]`
- NVT OIDs: `1.3.6.1.4.1.25623.1.0.{10000 + i}`
- Severity: cycle through `[2.1, 4.3, 5.0, 6.5, 7.5, 8.1, 9.8]`
- Description filler: repeat a fixed string to reach `result_payload_bytes`

### 3.3 Performance

The generator must be fast — building 10,000 results should take <100ms:
- Use `String::with_capacity(estimated_total_bytes)` 
- Append via `push_str` / `write!` — no intermediate allocations per result
- Avoid `format!` in tight loops where `write!` to a pre-allocated buffer suffices

---

## 4. Configuration API

### 4.1 `LargeReportConfig`

```rust
/// Configuration for synthetic large report generation.
pub struct LargeReportConfig {
    /// Number of <result> elements to generate.
    pub result_count: usize,
    
    /// Approximate bytes of filler text per result's <description>.
    /// Default: 512
    pub result_payload_bytes: usize,
}

impl Default for LargeReportConfig {
    fn default() -> Self {
        Self {
            result_count: 1_000,
            result_payload_bytes: 512,
        }
    }
}
```

### 4.2 Builder Integration

```rust
impl MockGmpServerBuilder {
    /// Enable large synthetic report generation for reports created via start_task.
    pub fn large_report(mut self, config: LargeReportConfig) -> Self;
}
```

### 4.3 Estimated Payload Sizes

| result_count | payload_bytes | Total Response (approx) |
|-------------|---------------|------------------------|
| 1,000 | 512 | ~1.5 MB |
| 5,000 | 512 | ~7 MB |
| 10,000 | 1,024 | ~25 MB |
| 50,000 | 512 | ~60 MB |
| 100,000 | 1,024 | ~250 MB |

---

## 5. Integration Tests

### 5.1 Test File

`crates/gvm-connection/tests/large_response.rs`

Feature-gated: `#[cfg(feature = "large-response-tests")]`

### 5.2 Test Cases

| # | Test | Config | Assertion |
|---|------|--------|-----------|
| 1 | `test_large_report_10mb` | 5,000 results × 1KB | Response ≥ 10MB, status 200, contains `<results>` |
| 2 | `test_large_report_deterministic` | 100 results × 512B | Two reads produce byte-identical responses |
| 3 | `test_large_report_result_count` | 1,000 results | `<result_count><full>1000</full>` present |
| 4 | `test_large_report_parseable` | 500 results | `Response::new(bytes)` succeeds, `is_success()` true |

### 5.3 CI Strategy

- **Default `cargo test`**: tests are not compiled (feature-gated)
- **`cargo test --features large-response-tests`**: runs with default config (5,000 results, ~10MB)
- **Nightly**: optionally run larger payload via env var
- **Timeout**: per-test timeout of 60 seconds (generous for 10MB over Unix socket)

---

## 6. Mock Server Changes

### 6.1 Files Modified

| File | Change |
|------|--------|
| `builder.rs` | Add `large_report` field + builder method |
| `handler.rs` | Pass config to `render_single_report_response`, generate large payload when config is set |
| `store.rs` | Store `LargeReportConfig` (or pass through handler) |
| `lib.rs` | Re-export `LargeReportConfig` |

### 6.2 Handler Logic

In `handle_get` → `get_reports` with a specific `report_id`:
1. Check if `LargeReportConfig` is set
2. If the requested report was created by `start_task`, generate synthetic results
3. Otherwise, use normal report rendering

This means the test flow is:
```
create_target → create_task → start_task → get_reports(report_id) → [large response]
```

---

## 7. Testing Strategy

### Unit Tests (in mock-server)
- `LargeReportConfig::default()` values
- Report generator produces valid XML for small N (10 results)
- Result UUIDs are deterministic
- Payload size is approximately correct

### Integration Tests (in gvm-connection)
- End-to-end: connect → auth → create lifecycle → large report read
- Feature-gated behind `large-response-tests`

---

## 8. Success Criteria

- [ ] `MockGmpServer` can be configured to produce 10MB+ report responses
- [ ] Response is valid, well-formed XML with correct GMP structure
- [ ] Generation is deterministic (same config → same bytes)
- [ ] Integration test validates rust-gvm reads the full response without timeout/panic/OOM
- [ ] Test is feature-gated so default `cargo test` remains fast
- [ ] Builder API is documented with usage example in rustdoc

---

## 9. Future Work

- **Streaming delivery**: Modify transport layer to write response in chunks (simulates real network behavior). Currently the full response is assembled as `Vec<u8>` before sending.
- **Benchmarking**: Add criterion benchmarks for report generation + parsing at various sizes.
- **Memory profiling**: Validate peak memory usage stays proportional to response size (not 2× due to buffering).

Related: #4 (streaming strategy), #30 (XmlReader buffer limits)
