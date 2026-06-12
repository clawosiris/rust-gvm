// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::users::*;
use gvm_gmp::UserAuthType;

#[test]
fn test_create_user_basic() {
    assert_eq!(
        xml(create_user("alice", Default::default())),
        "<create_user><name>alice</name></create_user>"
    );
}

#[test]
fn test_create_user_with_optionals() {
    assert_eq!(
        xml(create_user(
            "alice",
            UserOpts {
                comment: Some("c".into()),
                password: Some("secret".into()),
                host_access: Some("127.0.0.1".into()),
                role_ids: vec![id("r1"), id("r2")],
                auth_type: Some(UserAuthType::File),
            }
        )),
        "<create_user><name>alice</name><comment>c</comment><password>secret</password><hosts allow=\"1\">127.0.0.1</hosts><authentication>file</authentication><role id=\"r1\"/><role id=\"r2\"/></create_user>"
    );
}

#[test]
fn test_modify_user_with_host_access_modes() {
    assert_eq!(
        xml(modify_user(
            &id("u1"),
            UserOpts {
                host_access: Some(UserHostAccess::allow("192.0.2.0/24")),
                ..Default::default()
            }
        )),
        "<modify_user user_id=\"u1\"><hosts allow=\"1\">192.0.2.0/24</hosts></modify_user>"
    );
    assert_eq!(
        xml(modify_user(
            &id("u1"),
            UserOpts {
                host_access: Some(UserHostAccess::deny("192.0.2.0/24")),
                ..Default::default()
            }
        )),
        "<modify_user user_id=\"u1\"><hosts allow=\"0\">192.0.2.0/24</hosts></modify_user>"
    );
    assert_eq!(
        xml(modify_user(
            &id("u1"),
            UserOpts {
                host_access: Some(UserHostAccess::deny("")),
                ..Default::default()
            }
        )),
        "<modify_user user_id=\"u1\"><hosts allow=\"0\"></hosts></modify_user>"
    );
}

#[test]
fn test_user_get_modify_delete() {
    assert_eq!(
        xml(clone_user(&id("u1"))),
        "<create_user><copy>u1</copy></create_user>"
    );
    assert_eq!(
        xml(get_user(&id("u1"))),
        "<get_users details=\"1\" user_id=\"u1\"/>"
    );
    assert_eq!(
        xml(delete_user(&id("u1"), true)),
        "<delete_user ultimate=\"1\" user_id=\"u1\"/>"
    );
}
