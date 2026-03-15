#![allow(missing_docs)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::permissions::*;
use gvm_gmp::PermissionSubjectType;

#[test]
fn test_create_permission_basic() {
    assert_eq!(
        xml(create_permission(Default::default())),
        "<create_permission/>"
    );
}

#[test]
fn test_create_permission_with_optionals() {
    assert_eq!(
        xml(create_permission(PermissionOpts {
            comment: Some("c".into()),
            name: Some("get_tasks".into()),
            resource_id: Some(id("r1")),
            resource_type: Some("task".into()),
            subject_type: Some(PermissionSubjectType::Role),
            subject_id: Some(id("s1")),
        })),
        "<create_permission><comment>c</comment><name>get_tasks</name><resource_type>task</resource_type><resource_id>r1</resource_id><subject_type>role</subject_type><subject_id>s1</subject_id></create_permission>"
    );
}

#[test]
fn test_permission_get_modify_delete() {
    assert_eq!(
        xml(clone_permission(&id("p1"))),
        "<create_permission><copy>p1</copy></create_permission>"
    );
    assert_eq!(
        xml(get_permission(&id("p1"))),
        "<get_permissions details=\"1\" permission_id=\"p1\"/>"
    );
    assert_eq!(
        xml(delete_permission(&id("p1"), false)),
        "<delete_permission permission_id=\"p1\" ultimate=\"0\"/>"
    );
}
