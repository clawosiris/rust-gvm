mod common;

use common::{id, xml};
use gvm_gmp::commands::roles::*;

#[test]
fn test_create_role_basic() {
    assert_eq!(xml(create_role("role", Default::default())), "<create_role><name>role</name></create_role>");
}

#[test]
fn test_create_role_with_users() {
    assert_eq!(
        xml(create_role("role", RoleOpts { comment: Some("c".into()), users: vec!["alice".into()] })),
        "<create_role><name>role</name><comment>c</comment><users>alice</users></create_role>"
    );
}

#[test]
fn test_role_get_modify_delete() {
    assert_eq!(xml(clone_role(&id("r1"))), "<create_role><copy>r1</copy></create_role>");
    assert_eq!(xml(get_role(&id("r1"))), "<get_roles details=\"1\" role_id=\"r1\"/>");
    assert_eq!(xml(delete_role(&id("r1"), false)), "<delete_role role_id=\"r1\" ultimate=\"0\"/>");
}

