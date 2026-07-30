// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

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
                event_data: vec![AlertData::new("status", "Done")],
                condition: Some(AlertCondition::SeverityAtLeast),
                condition_data: vec![AlertData::new("severity", "5.5")],
                method: Some(AlertMethod::Email),
                method_data: vec![AlertData::new("to_address", "ops@example.com")],
                filter_id: Some(id("f1")),
                ..Default::default()
            }
        )),
        "<create_alert><name>a</name><comment>c</comment><event>Task run status changed<data>Done<name>status</name></data></event><condition>Severity at least<data>5.5<name>severity</name></data></condition><method>Email<data>ops@example.com<name>to_address</name></data></method><filter id=\"f1\"/></create_alert>"
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
                name: Some("renamed".into()),
                event: Some(AlertEvent::TaskRunStatusChanged),
                event_data: vec![AlertData::new("status", "Done")],
                condition: Some(AlertCondition::Always),
                method: Some(AlertMethod::SysLog),
                ..Default::default()
            }
        )),
        "<modify_alert alert_id=\"a1\"><name>renamed</name><event>Task run status changed<data>Done<name>status</name></data></event><condition>Always</condition><method>Syslog</method></modify_alert>"
    );
    assert_eq!(
        xml(delete_alert(&id("a1"), false)),
        "<delete_alert alert_id=\"a1\" ultimate=\"0\"/>"
    );
    assert_eq!(xml(test_alert(&id("a1"))), "<test_alert alert_id=\"a1\"/>");
}

#[test]
fn test_trigger_alert_builds_get_reports_command() {
    assert_eq!(
        xml(trigger_alert(
            &id("a1"),
            &id("r1"),
            TriggerAlertOpts {
                filter_string: Some("severity>5".into()),
                filter_id: Some(id("f1")),
                report_format_id: Some(id("rf1")),
                delta_report_id: Some(id("dr1")),
            }
        )),
        "<get_reports alert_id=\"a1\" delta_report_id=\"dr1\" filt_id=\"f1\" filter=\"severity&gt;5\" format_id=\"rf1\" report_id=\"r1\"/>"
    );
}
