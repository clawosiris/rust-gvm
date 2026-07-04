// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::operating_systems::*;

#[test]
fn test_get_operating_systems_with_options() {
    assert_eq!(
        xml(get_operating_systems(GetOperatingSystemsOpts {
            filter_string: Some("name=Debian".into()),
            filter_id: Some(id("f1")),
            details: Some(true),
        })),
        "<get_assets details=\"1\" filt_id=\"f1\" filter=\"name=Debian\" type=\"os\"/>"
    );
}

#[test]
fn test_get_operating_system() {
    assert_eq!(
        xml(get_operating_system(&id("os1"), None)),
        "<get_assets asset_id=\"os1\" type=\"os\"/>"
    );
    assert_eq!(
        xml(get_operating_system(&id("os1"), Some(false))),
        "<get_assets asset_id=\"os1\" details=\"0\" type=\"os\"/>"
    );
}

#[test]
fn test_modify_and_delete_operating_system() {
    assert_eq!(
        xml(modify_operating_system(&id("os1"), Some("updated"))),
        "<modify_asset asset_id=\"os1\"><comment>updated</comment></modify_asset>"
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
