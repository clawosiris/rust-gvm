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

#[test]
fn test_report_helper_commands() {
    assert_eq!(
        xml(get_report_hosts(
            &id("r1"),
            GetReportDetailsOpts {
                filter_string: Some("severity>5".into()),
                filter_id: Some(id("f1")),
                ignore_pagination: Some(true),
                details: Some(false),
            }
        )),
        "<get_report_hosts details=\"0\" filt_id=\"f1\" filter=\"severity&gt;5\" ignore_pagination=\"1\" report_id=\"r1\"/>"
    );
    assert_eq!(
        xml(get_report_ports(
            &id("r1"),
            GetReportDetailsOpts {
                ignore_pagination: Some(false),
                details: Some(true),
                ..Default::default()
            }
        )),
        "<get_report_ports details=\"1\" ignore_pagination=\"0\" report_id=\"r1\"/>"
    );
    assert_eq!(
        xml(get_report_applications(&id("r1"), Default::default())),
        "<get_report_applications details=\"1\" report_id=\"r1\"/>"
    );
    assert_eq!(
        xml(get_report_operating_systems(&id("r1"), Default::default())),
        "<get_report_operating_systems details=\"1\" report_id=\"r1\"/>"
    );
    assert_eq!(
        xml(get_report_cves(&id("r1"), Default::default())),
        "<get_report_cves details=\"1\" report_id=\"r1\"/>"
    );
}
