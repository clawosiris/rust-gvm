// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::results::{get_result, get_results, GetResultsOpts};

#[test]
fn test_get_results_basic() {
    assert_eq!(xml(get_results(Default::default())), "<get_results/>");
}

#[test]
fn test_get_results_with_filter_and_details() {
    assert_eq!(
        xml(get_results(GetResultsOpts {
            filter_string: Some("severity>5".into()),
            filter_id: Some(id("f1")),
            details: Some(true),
        })),
        "<get_results details=\"1\" filt_id=\"f1\" filter=\"severity&gt;5\"/>"
    );
}

#[test]
fn test_get_result_basic() {
    assert_eq!(
        xml(get_result(&id("res1"))),
        "<get_results details=\"1\" result_id=\"res1\"/>"
    );
}
