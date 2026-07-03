// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::scan_configs::*;

#[test]
fn test_create_scan_config_basic() {
    assert_eq!(
        xml(create_scan_config("cfg", None, Default::default())),
        "<create_config><name>cfg</name></create_config>"
    );
}

#[test]
fn test_create_scan_config_with_copy_and_options() {
    assert_eq!(
        xml(create_scan_config(
            "cfg",
            Some(&id("base1")),
            ConfigOpts {
                comment: Some("c".into()),
                usage_type: Some("scan".into()),
            }
        )),
        "<create_config><name>cfg</name><copy>base1</copy><comment>c</comment><usage_type>scan</usage_type></create_config>"
    );
}

#[test]
fn test_scan_config_get_delete_sync() {
    assert_eq!(
        xml(clone_scan_config(&id("c1"))),
        "<create_config><copy>c1</copy></create_config>"
    );
    assert_eq!(
        xml(get_scan_config(&id("c1"))),
        "<get_configs config_id=\"c1\" details=\"1\"/>"
    );
    assert_eq!(
        xml(sync_config(&id("c1"))),
        "<sync_config config_id=\"c1\"/>"
    );
}

#[test]
fn test_scan_config_preference_helpers_build_xml() {
    assert_eq!(
        xml(modify_scan_config_set_nvt_preference(
            &id("c1"),
            "timeout",
            "1.3.6.1.4.1.25623.1.0.1",
            Some("30"),
        )),
        "<modify_config config_id=\"c1\"><preference><nvt oid=\"1.3.6.1.4.1.25623.1.0.1\"/><name>timeout</name><value>MzA=</value></preference></modify_config>"
    );
    assert_eq!(
        xml(modify_scan_config_set_nvt_preference(
            &id("c1"),
            "timeout",
            "1.3.6.1.4.1.25623.1.0.1",
            None,
        )),
        "<modify_config config_id=\"c1\"><preference><nvt oid=\"1.3.6.1.4.1.25623.1.0.1\"/><name>timeout</name></preference></modify_config>"
    );
    assert_eq!(
        xml(modify_scan_config_set_scanner_preference(
            &id("c1"),
            "scanner-timeout",
            Some("45"),
        )),
        "<modify_config config_id=\"c1\"><preference><name>scanner-timeout</name><value>NDU=</value></preference></modify_config>"
    );
}

#[test]
fn test_scan_config_selection_helpers_build_xml() {
    assert_eq!(
        xml(modify_scan_config_set_nvt_selection(
            &id("c1"),
            "General",
            &["oid-1".into(), "oid-2".into()],
        )),
        "<modify_config config_id=\"c1\"><nvt_selection><family>General</family><nvt oid=\"oid-1\"/><nvt oid=\"oid-2\"/></nvt_selection></modify_config>"
    );
    assert_eq!(
        xml(modify_scan_config_set_family_selection(
            &id("c1"),
            &[
                NvtFamilySelection {
                    name: "General".into(),
                    growing: true,
                    all: false,
                },
                NvtFamilySelection {
                    name: "Web Servers".into(),
                    growing: false,
                    all: true,
                },
            ],
            true,
        )),
        "<modify_config config_id=\"c1\"><family_selection><growing>1</growing><family><name>General</name><all>0</all><growing>1</growing></family><family><name>Web Servers</name><all>1</all><growing>0</growing></family></family_selection></modify_config>"
    );
}

#[test]
fn test_policy_preference_helpers_build_xml() {
    assert_eq!(
        xml(modify_policy_set_nvt_preference(
            &id("p1"),
            "timeout",
            "1.3.6.1.4.1.25623.1.0.1",
            Some("30"),
        )),
        "<modify_config config_id=\"p1\"><preference><nvt oid=\"1.3.6.1.4.1.25623.1.0.1\"/><name>timeout</name><value>MzA=</value></preference></modify_config>"
    );
    assert_eq!(
        xml(modify_policy_set_scanner_preference(
            &id("p1"),
            "scanner-timeout",
            Some("45"),
        )),
        "<modify_config config_id=\"p1\"><preference><name>scanner-timeout</name><value>NDU=</value></preference></modify_config>"
    );
}

#[test]
fn test_policy_selection_helpers_build_xml() {
    assert_eq!(
        xml(modify_policy_set_nvt_selection(
            &id("p1"),
            "General",
            &["oid-1".into(), "oid-2".into()],
        )),
        "<modify_config config_id=\"p1\"><nvt_selection><family>General</family><nvt oid=\"oid-1\"/><nvt oid=\"oid-2\"/></nvt_selection></modify_config>"
    );
    assert_eq!(
        xml(modify_policy_set_family_selection(
            &id("p1"),
            &[NvtFamilySelection {
                name: "General".into(),
                growing: true,
                all: false,
            }],
            false,
        )),
        "<modify_config config_id=\"p1\"><family_selection><growing>0</growing><family><name>General</name><all>0</all><growing>1</growing></family></family_selection></modify_config>"
    );
}
