// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::resource_names::{
    get_resource_name, get_resource_names, GetResourceNamesOpts, ResourceType,
};

#[test]
fn test_get_resource_names_basic() {
    assert_eq!(
        xml(get_resource_names(GetResourceNamesOpts {
            resource_type: Some(ResourceType::Task),
            ..Default::default()
        })),
        "<get_resource_names type=\"TASK\"/>"
    );
}

#[test]
fn test_get_resource_names_with_options() {
    assert_eq!(
        xml(get_resource_names(GetResourceNamesOpts {
            resource_type: Some(ResourceType::Task),
            resource_id: Some(id("t1")),
            filter_string: Some("name=foo".into()),
            filter_id: Some(id("f1")),
        })),
        "<get_resource_names filt_id=\"f1\" filter=\"name=foo\" resource_id=\"t1\" type=\"TASK\"/>"
    );
}

#[test]
fn test_get_resource_name() {
    assert_eq!(
        xml(get_resource_name(&id("t1"), ResourceType::Task)),
        "<get_resource_names resource_id=\"t1\" type=\"TASK\"/>"
    );
}
