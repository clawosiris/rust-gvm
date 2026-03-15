# CODEX TASK: Address code review findings

Fix all issues identified in the Claude Code review, in priority order.

## 1. HIGH — Fix O(n²) re-parsing in XmlReader::check_complete

**File:** `crates/gvm-protocol/src/xml_reader.rs`

**Problem:** Every call to `feed()` re-parses the entire accumulated `self.buffer` from the start. For large responses this is O(n²).

**Fix:** Make the reader incremental. Track `depth: i32`, `seen_start: bool`, and `parse_offset: usize` as struct fields. On each `feed()`, only parse from `parse_offset` forward. When quick-xml returns `Eof` or errors mid-tag, save the current offset and continue from there on the next feed.

**Implementation approach:**
- Add fields: `depth: i32`, `seen_start: bool`, `parse_offset: usize`
- In `check_complete`, only parse `&self.buffer[self.parse_offset..]` 
- After each successful event, update `parse_offset` to `reader.buffer_position()`
- On `Eof` or `Err`, save `parse_offset` at the last successfully parsed position
- `reset()` must clear all new fields
- All existing tests must still pass

**IMPORTANT:** `Reader::from_str` doesn't have `buffer_position`. Use `Reader::from_reader` with a slice, or parse the full buffer but track state across calls. The simplest correct approach: keep `depth`/`seen_start` as struct fields, still parse the full buffer each time (which eliminates repeated work on the depth tracking), but use early-return once `is_complete` is set. The real O(n²) fix requires switching to `Reader::from_reader` with `BufRead` or tracking byte offsets manually.

Actually, the simplest correct approach that eliminates O(n²):
- Store `depth` and `seen_start` as struct fields
- On each `feed()`, parse ONLY the new data by creating a `Reader::from_str()` over just `&buffer[parse_offset..]`
- BUT this won't work because XML tags can span chunk boundaries

So the correct approach is:
- Keep parsing from the start each time (same as now) but store the struct-level `depth`/`seen_start`
- Once a parse run hits Eof/Err, record the byte position of the last complete event 
- On next feed, start from that saved position

Use `reader.buffer_position()` (available on `Reader<&[u8]>` via `from_reader`) to track the offset of the last successfully consumed event.

Concrete implementation:
```rust
pub struct XmlReader {
    buffer: Vec<u8>,
    complete: bool,
    depth: i32,
    seen_start: bool,
    /// Byte offset of the last fully-parsed event in `buffer`.
    resume_offset: usize,
}
```

In `check_complete`:
```rust
fn check_complete(&mut self) -> Result<(), ProtocolError> {
    if self.complete { return Ok(()); }
    
    let slice = match std::str::from_utf8(&self.buffer[self.resume_offset..]) {
        Ok(t) => t,
        Err(e) => {
            // There may be valid UTF-8 up to the error offset
            let valid_len = e.valid_up_to();
            if valid_len == 0 { return Ok(()); }
            &std::str::from_utf8(&self.buffer[self.resume_offset..self.resume_offset + valid_len])
                .map_err(|_| ())
                .unwrap_or_default()
                // Actually simpler: just return Ok(()) and wait for more data
        }
    };
    // ... parse slice, update self.depth/seen_start/resume_offset
}
```

Actually — keep it simple and correct. The key insight: we can safely re-parse from resume_offset because depth and seen_start are carried forward. We just need to handle the case where a tag straddles the resume boundary. Since we only update resume_offset after a successful event parse (not on Err/Eof), this is safe.

## 2. HIGH — Propagate feed() errors in UnixSocketConnection::read

**File:** `crates/gvm-connection/src/unix.rs`, line ~135

**Problem:** `let _ = xml_reader.feed(&buf[..n]);` silently discards errors. Malformed XML causes infinite loop until timeout.

**Fix:** Change to:
```rust
xml_reader.feed(&buf[..n]).map_err(|e| {
    ConnectionError::ReadFailed(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        e.to_string(),
    ))
})?;
```

## 3. MEDIUM — Cache parsed fields in Response

**File:** `crates/gvm-protocol/src/response.rs`

**Problem:** `status_code()`, `status_text()`, etc. each re-parse the XML. `raise_for_status()` triggers 3 parses.

**Fix:** Parse once on construction (or lazily via `OnceCell`). Add a private `ParsedHeader` struct:
```rust
use std::sync::OnceLock;

struct ParsedHeader {
    status_code: Option<u16>,
    status_text: Option<String>,
    root_element: Option<String>,
    id: Option<String>,
}

pub struct Response {
    data: Vec<u8>,
    header: OnceLock<ParsedHeader>,
}
```

Parse the root element's attributes once in a private `parse_header()` method, cache in `OnceLock`. All accessor methods call `self.header.get_or_init(|| self.parse_header())`.

`child_text()` still needs per-call parsing (different element each time), which is fine.

Add `#[must_use]` to `root_element_name()` and `id()`.

## 4. MEDIUM — Preserve io::Error source in GvmError::Connection

**File:** `crates/gvm-client/src/error.rs`

**Problem:** `GvmError::Connection(String)` loses the original `io::Error`.

**Fix:** Change the variant to hold the source error:
```rust
#[derive(Debug, Error)]
pub enum GvmError {
    /// Transport-level failure.
    #[error("connection error: {0}")]
    Connection(#[from] gvm_connection::ConnectionError),
    // ... rest unchanged
}
```

Remove the manual `From<ConnectionError>` impl. Keep `Timeout` extraction if desired by matching in relevant call sites, or just let `ConnectionError::Timeout` flow through as `Connection(ConnectionError::Timeout(...))`.

Actually — to keep Timeout as a separate variant, do:
```rust
impl From<ConnectionError> for GvmError {
    fn from(value: ConnectionError) -> Self {
        match value {
            ConnectionError::Timeout(d) => Self::Timeout(d),
            other => Self::Connection(other),
        }
    }
}

#[derive(Debug, Error)]
pub enum GvmError {
    #[error("connection error: {0}")]
    Connection(#[source] ConnectionError),
    // ...
}
```

This preserves the `source()` chain. Remove the `Io` variant if it's unreachable now.

## 5. MEDIUM — Simplify GmpVersioned boilerplate

**File:** `crates/gvm-client/src/lib.rs`

**Problem:** 5 empty newtypes + enum with 5 identical match arms per method.

**Fix:** Add a private helper method to extract the inner client:
```rust
impl<C: GvmConnection> GmpVersioned<C> {
    fn inner(&self) -> &GmpClient<C> {
        match self {
            Self::V224(c) => &c.0,
            Self::V225(c) => &c.0,
            Self::V226(c) => &c.0,
            Self::V227(c) => &c.0,
            Self::Next(c) => &c.0,
        }
    }
    
    fn inner_mut(&mut self) -> &mut GmpClient<C> {
        match self {
            Self::V224(c) => &mut c.0,
            Self::V225(c) => &mut c.0,
            Self::V226(c) => &mut c.0,
            Self::V227(c) => &mut c.0,
            Self::Next(c) => &mut c.0,
        }
    }
}
```

Then each public method just calls `self.inner().version()` or `self.inner_mut().send(request).await`.

Also make the newtype fields private (remove `pub` from tuple field).

## 6. LOW — Add #[must_use] to Response methods

**File:** `crates/gvm-protocol/src/response.rs`

Add `#[must_use]` to `root_element_name()` and `id()`.

## Validation

After all fixes:
1. `cargo test --workspace` — all pass
2. `cargo clippy --workspace --all-targets --all-features` — no new warnings
3. No behavioral changes to any public API (except `GvmError::Connection` now holds `ConnectionError` instead of `String`, and version newtype fields are private)
