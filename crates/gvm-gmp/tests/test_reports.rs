// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::reports::*;

#[test]
fn test_create_report_basic() {
    assert_eq!(
        xml(create_report(&id("t1"), Default::default())),
        "<create_report><task id=\"t1\"/></create_report>"
    );
}

#[test]
fn test_create_report_with_optionals() {
    assert_eq!(
        xml(create_report(
            &id("t1"),
            CreateReportOpts {
                format_id: Some(id("rf1")),
                filter_id: Some(id("f1")),
                ignore_pagination: Some(true),
            }
        )),
        "<create_report ignore_pagination=\"1\"><report_format id=\"rf1\"/><task id=\"t1\"/><filter id=\"f1\"/></create_report>"
    );
}

#[test]
fn test_report_get_and_delete() {
    assert_eq!(
        xml(get_report(&id("r1"))),
        "<get_reports details=\"1\" report_id=\"r1\"/>"
    );
    assert_eq!(
        xml(delete_report(&id("r1"), false)),
        "<delete_report report_id=\"r1\" ultimate=\"0\"/>"
    );
}
