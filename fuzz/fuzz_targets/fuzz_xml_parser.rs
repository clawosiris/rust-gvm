// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Fuzz target for low-level XML response parsing.
//!
//! Tests the `gvm-protocol` Response type which wraps raw XML data.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to interpret bytes as UTF-8 XML
    if let Ok(s) = std::str::from_utf8(data) {
        // Construct a Response from the string data
        let response = gvm_protocol::Response::from(s);
        // Access data to ensure no panics
        let _ = response.data();
        let _ = response.status();
        let _ = response.status_text();
    }
});
