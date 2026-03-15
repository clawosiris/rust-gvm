mod common;

use common::{id, xml};
use gvm_gmp::commands::hosts::*;

#[test]
fn test_create_host_basic() {
    assert_eq!(xml(create_host(Default::default())), "<create_asset><asset_type>host</asset_type></create_asset>");
}

#[test]
fn test_create_host_with_value_and_comment() {
    assert_eq!(
        xml(create_host(HostOpts { comment: Some("c".into()), value: Some("1.1.1.1".into()) })),
        "<create_asset><asset_type>host</asset_type><comment>c</comment><value>1.1.1.1</value></create_asset>"
    );
}

#[test]
fn test_host_get_modify_delete() {
    assert_eq!(xml(get_host(&id("h1"))), "<get_assets asset_id=\"h1\" asset_type=\"host\" details=\"1\"/>");
    assert_eq!(xml(delete_host(&id("h1"), false)), "<delete_asset asset_id=\"h1\" ultimate=\"0\"/>");
}

