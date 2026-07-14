// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::assets::*;
use gvm_gmp::commands::hosts::{
    create_host, delete_host, get_host, get_hosts, modify_host, HostOpts,
};
use gvm_gmp::commands::operating_systems::{
    delete_operating_system, get_operating_system, get_operating_systems, modify_operating_system,
    GetOperatingSystemsOpts,
};

#[test]
fn test_create_asset_xml() {
    assert_eq!(
        xml(create_asset(CreateAssetOpts {
            asset_type: AssetType::Host,
            comment: Some("c".into()),
            value: Some("1.1.1.1".into()),
        })),
        "<create_asset><asset><type>host</type><name>1.1.1.1</name><comment>c</comment></asset></create_asset>"
    );
}

#[test]
fn test_get_assets_with_custom_type_xml() {
    assert_eq!(
        xml(get_assets(GetAssetsOpts {
            type_: Some(AssetType::custom("firmware")),
            details: Some(true),
            ..Default::default()
        })),
        "<get_assets details=\"1\" type=\"firmware\"/>"
    );
}

#[test]
fn test_asset_type_alias_emits_only_canonical_type() {
    assert_eq!(
        xml(get_assets(GetAssetsOpts {
            asset_type: Some(AssetType::Host),
            ..Default::default()
        })),
        "<get_assets type=\"host\"/>"
    );
    assert_eq!(
        xml(get_assets(GetAssetsOpts {
            asset_type: Some(AssetType::Host),
            type_: Some(AssetType::OperatingSystem),
            ..Default::default()
        })),
        "<get_assets type=\"os\"/>"
    );
}

#[test]
fn test_modify_delete_asset_xml() {
    assert_eq!(
        xml(modify_asset(
            &id("a1"),
            ModifyAssetOpts {
                comment: Some("updated".into()),
                value: Some("v".into()),
            },
        )),
        "<modify_asset asset_id=\"a1\"><comment>updated</comment></modify_asset>"
    );
    assert_eq!(
        xml(delete_asset(
            &id("a1"),
            DeleteAssetOpts {
                ultimate: Some(false),
            },
        )),
        "<delete_asset asset_id=\"a1\"/>"
    );
}

#[test]
fn test_host_wrappers_match_generic_xml() {
    let create_opts = HostOpts {
        comment: Some("c".into()),
        value: Some("1.1.1.1".into()),
    };
    assert_eq!(
        xml(create_host(create_opts.clone())),
        xml(create_asset(CreateAssetOpts {
            asset_type: AssetType::Host,
            comment: create_opts.comment.clone(),
            value: create_opts.value.clone(),
        }))
    );

    assert_eq!(
        xml(get_host(&id("h1"))),
        xml(get_assets(GetAssetsOpts {
            asset_id: Some(id("h1")),
            type_: Some(AssetType::Host),
            details: Some(true),
            ..Default::default()
        }))
    );

    assert_eq!(
        xml(modify_host(&id("h1"), create_opts.clone())),
        xml(modify_asset(
            &id("h1"),
            ModifyAssetOpts {
                comment: create_opts.comment,
                value: None,
            },
        ))
    );
    assert_eq!(
        xml(delete_host(&id("h1"), true)),
        xml(delete_asset(&id("h1"), DeleteAssetOpts { ultimate: None },))
    );
}

#[test]
fn test_operating_system_wrapper_xml_regression() {
    assert_eq!(
        xml(get_operating_systems(GetOperatingSystemsOpts {
            filter_string: Some("name=Debian".into()),
            filter_id: Some(id("f1")),
            details: Some(true),
        })),
        "<get_assets details=\"1\" filt_id=\"f1\" filter=\"name=Debian\" type=\"os\"/>"
    );
    assert_eq!(
        xml(get_operating_system(&id("os1"), Some(false))),
        "<get_assets asset_id=\"os1\" details=\"0\" type=\"os\"/>"
    );
    assert_eq!(
        xml(modify_operating_system(&id("os1"), None)),
        "<modify_asset asset_id=\"os1\"><comment></comment></modify_asset>"
    );
    assert_eq!(
        xml(delete_operating_system(&id("os1"))),
        "<delete_asset asset_id=\"os1\"/>"
    );
}

#[test]
fn test_get_hosts_wrapper_regression() {
    assert_eq!(
        xml(get_hosts(Default::default())),
        "<get_assets type=\"host\"/>"
    );
}
