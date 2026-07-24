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
fn test_import_report_basic() {
    let report_xml = r#"<report id="r1"><name>Imported</name></report>"#;

    assert_eq!(
        xml(import_report(report_xml, &id("t1"), Default::default()).expect("valid report XML")),
        r#"<create_report><task id="t1"/><report id="r1"><name>Imported</name></report></create_report>"#
    );
}

#[test]
fn test_import_report_with_in_assets() {
    let report_xml = r#"<report id="r1"><name>Imported</name></report>"#;

    assert_eq!(
        xml(import_report(
            report_xml,
            &id("t1"),
            ImportReportOpts {
                in_assets: Some(false),
            },
        )
        .expect("valid report XML")),
        r#"<create_report><task id="t1"/><in_assets>0</in_assets><report id="r1"><name>Imported</name></report></create_report>"#
    );
    assert_eq!(
        xml(import_report(
            report_xml,
            &id("t1"),
            ImportReportOpts {
                in_assets: Some(true),
            },
        )
        .expect("valid report XML")),
        r#"<create_report><task id="t1"/><in_assets>1</in_assets><report id="r1"><name>Imported</name></report></create_report>"#
    );
}

#[test]
fn test_import_report_rejects_invalid_report_xml() {
    assert!(import_report("report", &id("t1"), Default::default()).is_err());
    assert!(import_report("", &id("t1"), Default::default()).is_err());
    assert!(import_report("<foo/>", &id("t1"), Default::default()).is_err());
    assert!(import_report(
        r#"<?xml version="1.0"?><report id="r1"/>"#,
        &id("t1"),
        Default::default()
    )
    .is_err());
    assert!(import_report(
        r#"<!DOCTYPE report><report id="r1"/>"#,
        &id("t1"),
        Default::default()
    )
    .is_err());
    assert!(import_report(
        r#"<report id="r1"/></create_report><delete_task/>"#,
        &id("t1"),
        Default::default()
    )
    .is_err());
}

#[test]
fn test_report_get_and_delete() {
    assert_eq!(
        xml(get_report(&id("r1"))),
        "<get_reports details=\"1\" report_id=\"r1\"/>"
    );
    assert_eq!(
        xml(get_report_export(&id("r1"), &id("rf1"))),
        "<get_reports details=\"1\" format_id=\"rf1\" ignore_pagination=\"1\" report_id=\"r1\"/>"
    );
    assert_eq!(
        xml(get_reports(GetReportsOpts {
            report_id: Some(id("r1")),
            details: Some(false),
            ..Default::default()
        })),
        "<get_reports details=\"0\" report_id=\"r1\"/>"
    );
    assert_eq!(
        xml(delete_report(&id("r1"), false)),
        "<delete_report report_id=\"r1\" ultimate=\"0\"/>"
    );
}

#[test]
fn test_get_scan_report_with_filters() {
    assert_eq!(
        xml(get_scan_report(
            &id("r1"),
            GetScanReportOpts {
                filter_string: Some("levels=chml min_qod=70".into()),
                filter_id: Some(id("f1")),
            },
        )),
        "<get_scan_report filt_id=\"f1\" filter=\"levels=chml min_qod=70\" scan_report_id=\"r1\"/>"
    );
}

#[test]
fn test_get_scan_report_without_filters() {
    assert_eq!(
        xml(get_scan_report(&id("r1"), Default::default())),
        "<get_scan_report scan_report_id=\"r1\"/>"
    );
}

#[test]
fn test_report_export_with_report_config() {
    let mut opts = GetReportExportOpts::new(id("rf1"));
    opts.report_config_id = Some(id("rc1"));

    assert_eq!(
        xml(get_report_export_with_opts(&id("r1"), opts)),
        "<get_reports config_id=\"rc1\" details=\"1\" format_id=\"rf1\" ignore_pagination=\"1\" report_id=\"r1\"/>"
    );
}

#[test]
fn test_report_export_with_filter_string() {
    let mut opts = GetReportExportOpts::new(id("rf1"));
    opts.filter_string = Some("severity>5".into());

    assert_eq!(
        xml(get_report_export_with_opts(&id("r1"), opts)),
        "<get_reports details=\"1\" filter=\"severity&gt;5\" format_id=\"rf1\" ignore_pagination=\"1\" report_id=\"r1\"/>"
    );
}

#[test]
fn test_report_export_with_filter_id() {
    let mut opts = GetReportExportOpts::new(id("rf1"));
    opts.filter_id = Some(id("f1"));

    assert_eq!(
        xml(get_report_export_with_opts(&id("r1"), opts)),
        "<get_reports details=\"1\" filt_id=\"f1\" format_id=\"rf1\" ignore_pagination=\"1\" report_id=\"r1\"/>"
    );
}

#[test]
fn test_report_export_with_combined_options() {
    let mut opts = GetReportExportOpts::new(id("rf1"));
    opts.report_config_id = Some(id("rc1"));
    opts.filter_string = Some("severity>5".into());
    opts.filter_id = Some(id("f1"));

    assert_eq!(
        xml(get_report_export_with_opts(&id("r1"), opts)),
        "<get_reports config_id=\"rc1\" details=\"1\" filt_id=\"f1\" filter=\"severity&gt;5\" format_id=\"rf1\" ignore_pagination=\"1\" report_id=\"r1\"/>"
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
