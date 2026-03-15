mod common;

use common::{id, xml};
use gvm_gmp::commands::groups::*;

#[test]
fn test_create_group_basic() {
    assert_eq!(xml(create_group("g", Default::default())), "<create_group><name>g</name></create_group>");
}

#[test]
fn test_create_group_with_users() {
    assert_eq!(
        xml(create_group("g", GroupOpts { comment: Some("c".into()), users: vec!["alice".into(), "bob".into()] })),
        "<create_group><name>g</name><comment>c</comment><users>alice,bob</users></create_group>"
    );
}

#[test]
fn test_group_get_modify_delete() {
    assert_eq!(xml(clone_group(&id("g1"))), "<create_group><copy>g1</copy></create_group>");
    assert_eq!(xml(get_group(&id("g1"))), "<get_groups details=\"1\" group_id=\"g1\"/>");
    assert_eq!(xml(delete_group(&id("g1"), false)), "<delete_group group_id=\"g1\" ultimate=\"0\"/>");
}

