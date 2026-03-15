// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::overrides::*;

#[test]
fn test_create_override_basic() {
    assert_eq!(
        xml(create_override("oid", Default::default())),
        "<create_override><nvt oid=\"oid\"/></create_override>"
    );
}

#[test]
fn test_create_override_with_optionals() {
    assert_eq!(
        xml(create_override(
            "oid",
            OverrideOpts {
                text: Some("body".into()),
                hosts: vec!["1.1.1.1".into()],
                port: Some("22".into()),
                severity: Some("5.0".into()),
                new_severity: Some("7.5".into()),
                task_id: Some(id("t1")),
                result_id: Some(id("r1")),
                active: Some(true),
            }
        )),
        "<create_override><nvt oid=\"oid\"/><text>body</text><hosts>1.1.1.1</hosts><port>22</port><severity>5.0</severity><new_severity>7.5</new_severity><task id=\"t1\"/><result id=\"r1\"/><active>1</active></create_override>"
    );
}

#[test]
fn test_override_get_modify_delete() {
    assert_eq!(
        xml(clone_override(&id("o1"))),
        "<create_override><copy>o1</copy></create_override>"
    );
    assert_eq!(
        xml(get_override(&id("o1"))),
        "<get_overrides details=\"1\" override_id=\"o1\"/>"
    );
    assert_eq!(
        xml(delete_override(&id("o1"), false)),
        "<delete_override override_id=\"o1\" ultimate=\"0\"/>"
    );
}
