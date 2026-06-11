// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use std::collections::HashMap;

use common::{id, xml};
use gvm_gmp::commands::alerts::*;
use gvm_gmp::{AlertCondition, AlertEvent, AlertMethod};

#[test]
fn test_create_alert_basic() {
    assert_eq!(
        xml(create_alert("a", Default::default())),
        "<create_alert><name>a</name></create_alert>"
    );
}

#[test]
fn test_create_alert_with_all_optionals() {
    assert_eq!(
        xml(create_alert(
            "a",
            AlertOpts {
                comment: Some("c".into()),
                event: Some(AlertEvent::TaskRunStatusChanged),
                event_data: HashMap::from([(String::from("event_key"), String::from("event_value"))]),
                condition: Some(AlertCondition::Always),
                condition_data: HashMap::from([(
                    String::from("condition_key"),
                    String::from("condition_value"),
                )]),
                method: Some(AlertMethod::Email),
                method_data: HashMap::from([(String::from("method_key"), String::from("method_value"))]),
                filter_id: Some(id("f1")),
            }
        )),
        "<create_alert><name>a</name><comment>c</comment><event>Task run status changed<data>event_value<name>event_key</name></data></event><condition>Always<data>condition_value<name>condition_key</name></data></condition><method>Email<data>method_value<name>method_key</name></data></method><filter id=\"f1\"/></create_alert>"
    );
}

#[test]
fn test_alert_get_modify_delete_and_test() {
    assert_eq!(
        xml(clone_alert(&id("a1"))),
        "<create_alert><copy>a1</copy></create_alert>"
    );
    assert_eq!(
        xml(get_alert(&id("a1"))),
        "<get_alerts alert_id=\"a1\" details=\"1\"/>"
    );
    assert_eq!(
        xml(modify_alert(
            &id("a1"),
            AlertOpts {
                event: Some(AlertEvent::TaskRunStatusChanged),
                event_data: HashMap::from([(String::from("status"), String::from("scan"))]),
                condition: Some(AlertCondition::Always),
                condition_data: HashMap::from([(String::from("threshold"), String::from("9.5"))]),
                method: Some(AlertMethod::SysLog),
                method_data: HashMap::from([(String::from("facility"), String::from("local0"))]),
                ..Default::default()
            }
        )),
        "<modify_alert alert_id=\"a1\"><event>Task run status changed<data>scan<name>status</name></data></event><condition>Always<data>9.5<name>threshold</name></data></condition><method>Syslog<data>local0<name>facility</name></data></method></modify_alert>"
    );
    assert_eq!(
        xml(delete_alert(&id("a1"), false)),
        "<delete_alert alert_id=\"a1\" ultimate=\"0\"/>"
    );
    assert_eq!(xml(test_alert(&id("a1"))), "<test_alert alert_id=\"a1\"/>");
}
