// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::port_lists::*;
use gvm_gmp::PortRangeType;

#[test]
fn test_create_port_list_basic() {
    assert_eq!(
        xml(create_port_list("ports", Default::default())),
        "<create_port_list><name>ports</name></create_port_list>"
    );
}

#[test]
fn test_create_port_list_and_range_with_options() {
    assert_eq!(
        xml(create_port_list("ports", PortListOpts { comment: Some("c".into()), port_range: Some("T:1-5".into()) })),
        "<create_port_list><name>ports</name><comment>c</comment><port_range>T:1-5</port_range></create_port_list>"
    );
    assert_eq!(
        xml(create_port_range(&id("pl1"), PortRangeType::Tcp, 1, 5)),
        "<create_port_range end=\"5\" port_list_id=\"pl1\" start=\"1\" type=\"TCP\"/>"
    );
}

#[test]
fn test_port_list_get_delete_commands() {
    assert_eq!(
        xml(clone_port_list(&id("pl1"))),
        "<create_port_list><copy>pl1</copy></create_port_list>"
    );
    assert_eq!(
        xml(get_port_list(&id("pl1"))),
        "<get_port_lists details=\"1\" port_list_id=\"pl1\"/>"
    );
    assert_eq!(
        xml(delete_port_range(&id("pr1"))),
        "<delete_port_range port_range_id=\"pr1\"/>"
    );
}
