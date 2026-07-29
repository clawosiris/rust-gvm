// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

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
fn test_create_permission_with_nested_subject() {
    assert_eq!(
        xml(create_permission(PermissionOpts {
            name: Some("get_tasks".into()),
            subject_type: Some(PermissionSubjectType::Role),
            subject_id: Some(id("s1")),
            ..Default::default()
        })),
        "<create_permission><name>get_tasks</name><subject id=\"s1\"><type>role</type></subject></create_permission>"
    );
}

#[test]
fn test_create_permission_with_nested_resource() {
    assert_eq!(
        xml(create_permission(PermissionOpts {
            name: Some("get_tasks".into()),
            resource_id: Some(id("r1")),
            resource_type: Some("task".into()),
            ..Default::default()
        })),
        "<create_permission><name>get_tasks</name><resource id=\"r1\"><type>task</type></resource></create_permission>"
    );
}

#[test]
fn test_create_permission_with_nested_subject_and_resource() {
    assert_eq!(
        xml(create_permission(PermissionOpts {
            comment: Some("c".into()),
            name: Some("get_tasks".into()),
            resource_id: Some(id("r1")),
            resource_type: Some("task".into()),
            subject_type: Some(PermissionSubjectType::Role),
            subject_id: Some(id("s1")),
        })),
        "<create_permission><comment>c</comment><name>get_tasks</name><resource id=\"r1\"><type>task</type></resource><subject id=\"s1\"><type>role</type></subject></create_permission>"
    );
}

#[test]
fn test_modify_permission_with_nested_subject_and_resource() {
    assert_eq!(
        xml(modify_permission(
            &id("p1"),
            PermissionOpts {
                resource_id: Some(id("r1")),
                resource_type: Some("task".into()),
                subject_type: Some(PermissionSubjectType::Role),
                subject_id: Some(id("s1")),
                ..Default::default()
            }
        )),
        "<modify_permission permission_id=\"p1\"><resource id=\"r1\"><type>task</type></resource><subject id=\"s1\"><type>role</type></subject></modify_permission>"
    );
}

#[test]
fn test_permission_partial_references_remain_nested() {
    assert_eq!(
        xml(create_permission(PermissionOpts {
            resource_id: Some(id("r1")),
            subject_type: Some(PermissionSubjectType::Role),
            ..Default::default()
        })),
        "<create_permission><resource id=\"r1\"/><subject><type>role</type></subject></create_permission>"
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
