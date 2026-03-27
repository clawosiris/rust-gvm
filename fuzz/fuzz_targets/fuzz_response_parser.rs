// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Fuzz target for high-level GMP response model parsing.
//!
//! Tests the typed response parsers in `gvm-gmp::responses`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to interpret bytes as UTF-8 XML
    if let Ok(s) = std::str::from_utf8(data) {
        let response = gvm_protocol::Response::from(s);

        // Try parsing as various response types — all should handle malformed input gracefully
        let _ = gvm_gmp::responses::version::GetVersionResponse::from_response(&response);
        let _ = gvm_gmp::responses::auth::AuthenticateResponse::from_response(&response);
        let _ = gvm_gmp::responses::target::GetTargetsResponse::from_response(&response);
        let _ = gvm_gmp::responses::task::GetTasksResponse::from_response(&response);
        let _ = gvm_gmp::responses::report::GetReportsResponse::from_response(&response);
        let _ = gvm_gmp::responses::result::GetResultsResponse::from_response(&response);
        let _ = gvm_gmp::responses::nvt::GetNvtsResponse::from_response(&response);
        let _ = gvm_gmp::responses::feed::GetFeedsResponse::from_response(&response);
        let _ = gvm_gmp::responses::scanner::GetScannersResponse::from_response(&response);
        let _ = gvm_gmp::responses::scan_config::GetScanConfigsResponse::from_response(&response);
        let _ = gvm_gmp::responses::port_list::GetPortListsResponse::from_response(&response);
        let _ = gvm_gmp::responses::secinfo::GetCvesResponse::from_response(&response);
        let _ = gvm_gmp::responses::secinfo::GetCpesResponse::from_response(&response);
    }
});
