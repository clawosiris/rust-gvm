// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::hosts::*;

#[test]
fn test_create_host_basic() {
    assert_eq!(
        xml(create_host(Default::default())),
        "<create_asset><asset><type>host</type><name></name></asset></create_asset>"
    );
}

#[test]
fn test_create_host_with_value_and_comment() {
    assert_eq!(
        xml(create_host(HostOpts { comment: Some("c".into()), value: Some("1.1.1.1".into()) })),
        "<create_asset><asset><type>host</type><name>1.1.1.1</name><comment>c</comment></asset></create_asset>"
    );
}

#[test]
fn test_create_host_named_constructor() {
    assert_eq!(
        xml(create_host(HostOpts::named("2001:db8::1"))),
        "<create_asset><asset><type>host</type><name>2001:db8::1</name></asset></create_asset>"
    );
}

#[test]
fn test_host_get_modify_delete() {
    assert_eq!(
        xml(get_host(&id("h1"))),
        "<get_assets asset_id=\"h1\" details=\"1\" type=\"host\"/>"
    );
    assert_eq!(
        xml(delete_host(&id("h1"), false)),
        "<delete_asset asset_id=\"h1\"/>"
    );
}
