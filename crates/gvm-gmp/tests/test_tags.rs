// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::tags::*;
use gvm_gmp::{EntityType, SeverityLevel};

#[test]
fn test_create_tag_basic() {
    assert_eq!(
        xml(create_tag("tag", Default::default())),
        "<create_tag><name>tag</name></create_tag>"
    );
}

#[test]
fn test_create_tag_with_optionals() {
    assert_eq!(
        xml(create_tag(
            "tag",
            TagOpts {
                comment: Some("c".into()),
                value: Some("blue".into()),
                resource_type: Some(EntityType::Task),
                resource_id: Some(id("t1")),
                severity: Some(SeverityLevel::High),
                active: Some(true),
            }
        )),
        "<create_tag><name>tag</name><comment>c</comment><value>blue</value><resource_type>task</resource_type><resource_id>t1</resource_id><severity>high</severity><active>1</active></create_tag>"
    );
}

#[test]
fn test_tag_get_modify_delete() {
    assert_eq!(
        xml(clone_tag(&id("tg1"))),
        "<create_tag><copy>tg1</copy></create_tag>"
    );
    assert_eq!(
        xml(get_tag(&id("tg1"))),
        "<get_tags details=\"1\" tag_id=\"tg1\"/>"
    );
    assert_eq!(
        xml(delete_tag(&id("tg1"), false)),
        "<delete_tag tag_id=\"tg1\" ultimate=\"0\"/>"
    );
}
