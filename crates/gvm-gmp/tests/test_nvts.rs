// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::nvts::{
    get_nvt, get_nvt_families, get_nvts, get_scan_config_nvt, get_scan_config_nvts, GetNvtsOpts,
};

#[test]
fn test_get_nvts_basic() {
    assert_eq!(xml(get_nvts(Default::default())), "<get_nvts/>");
}

#[test]
fn test_get_nvts_with_options() {
    assert_eq!(
        xml(get_nvts(GetNvtsOpts {
            filter_string: Some("family=foo".into()),
            filter_id: Some(id("f1")),
            details: Some(true),
            ..Default::default()
        })),
        "<get_nvts details=\"1\" filt_id=\"f1\" filter=\"family=foo\"/>"
    );
}

#[test]
fn test_get_scan_config_nvts_with_options() {
    assert_eq!(
        xml(get_scan_config_nvts(GetNvtsOpts {
            details: Some(true),
            preferences: Some(true),
            preference_count: Some(false),
            timeout: Some(true),
            config_id: Some(id("config-1")),
            preferences_config_id: Some(id("config-2")),
            family: Some("General".into()),
            sort_order: Some("ascending".into()),
            sort_field: Some("name".into()),
            ..Default::default()
        })),
        "<get_nvts config_id=\"config-1\" details=\"1\" family=\"General\" preference_count=\"0\" preferences=\"1\" preferences_config_id=\"config-2\" sort_field=\"name\" sort_order=\"ascending\" timeout=\"1\"/>"
    );
}

#[test]
fn test_get_nvt_and_families() {
    assert_eq!(
        xml(get_nvt("1.3.6.1")),
        "<get_nvts details=\"1\" nvt_oid=\"1.3.6.1\"/>"
    );
    assert_eq!(
        xml(get_scan_config_nvt("1.3.6.1")),
        "<get_nvts details=\"1\" nvt_oid=\"1.3.6.1\" preference_count=\"1\" preferences=\"1\"/>"
    );
    assert_eq!(xml(get_nvt_families()), "<get_nvt_families/>");
}
