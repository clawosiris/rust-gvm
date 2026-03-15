// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::report_formats::*;
use gvm_gmp::ReportFormatType;

#[test]
fn test_create_report_format_basic() {
    assert_eq!(
        xml(create_report_format("rf", Default::default())),
        "<create_report_format><name>rf</name></create_report_format>"
    );
}

#[test]
fn test_create_report_format_with_optionals() {
    assert_eq!(
        xml(create_report_format(
            "rf",
            ReportFormatOpts {
                comment: Some("c".into()),
                content_type: Some("text/xml".into()),
                format_type: Some(ReportFormatType::Pdf),
            }
        )),
        "<create_report_format><name>rf</name><comment>c</comment><content_type>text/xml</content_type><type>pdf</type></create_report_format>"
    );
}

#[test]
fn test_report_format_get_delete_verify() {
    assert_eq!(
        xml(get_report_format(&id("rf1"))),
        "<get_report_formats details=\"1\" report_format_id=\"rf1\"/>"
    );
    assert_eq!(
        xml(delete_report_format(&id("rf1"), false)),
        "<delete_report_format report_format_id=\"rf1\" ultimate=\"0\"/>"
    );
    assert_eq!(
        xml(verify_report_format(&id("rf1"))),
        "<verify_report_format report_format_id=\"rf1\"/>"
    );
}
