// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::xml;
use gvm_gmp::commands::report_configs::*;

#[test]
fn test_create_report_config_basic() {
    assert_eq!(
        xml(create_report_config("cfg", "rf1")),
        "<create_report_config><name>cfg</name><report_format_id>rf1</report_format_id></create_report_config>"
    );
    assert_eq!(
        xml(clone_report_config("cfg1")),
        "<create_report_config><copy>cfg1</copy></create_report_config>"
    );
}

#[test]
fn test_create_report_config_with_optionals() {
    assert_eq!(
        xml(create_report_config_opts(
            "cfg",
            "rf1",
            CreateReportConfigOpts {
                comment: Some("comment".into()),
            }
        )),
        "<create_report_config><name>cfg</name><report_format_id>rf1</report_format_id><comment>comment</comment></create_report_config>"
    );
}

#[test]
fn test_get_report_configs_variants() {
    assert_eq!(xml(get_report_configs()), "<get_report_configs/>");
    assert_eq!(
        xml(get_report_configs_opts(GetReportConfigsOpts {
            filter: Some("name=foo".into()),
            first: Some(5),
            rows: Some(10),
        })),
        "<get_report_configs filter=\"name=foo\" first=\"5\" rows=\"10\"/>"
    );
    assert_eq!(
        xml(get_report_config("cfg1")),
        "<get_report_configs report_config_id=\"cfg1\"/>"
    );
}

#[test]
fn test_modify_and_delete_report_config() {
    assert_eq!(
        xml(modify_report_config(
            "cfg1",
            ModifyReportConfigOpts {
                name: Some("renamed".into()),
                comment: Some("updated".into()),
            }
        )),
        "<modify_report_config report_config_id=\"cfg1\"><name>renamed</name><comment>updated</comment></modify_report_config>"
    );
    assert_eq!(
        xml(delete_report_config("cfg1")),
        "<delete_report_config report_config_id=\"cfg1\"/>"
    );
    assert_eq!(
        xml(delete_report_config_opts(
            "cfg1",
            DeleteReportConfigOpts {
                ultimate: Some(true),
            }
        )),
        "<delete_report_config report_config_id=\"cfg1\" ultimate=\"1\"/>"
    );
}
