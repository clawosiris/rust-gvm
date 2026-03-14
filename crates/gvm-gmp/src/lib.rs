//! GMP command builders and response types.
//!
//! Type-safe command construction and response parsing for each GMP version
//! (22.4 through 22.8+). Commands are built as [`Request`] objects that serialize
//! to GMP XML bytes.
