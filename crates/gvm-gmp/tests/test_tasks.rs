// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::tasks::*;
use gvm_gmp::HostsOrdering;

#[test]
fn test_create_task_basic() {
    assert_eq!(
        xml(create_task("foo", &id("c1"), &id("t1"), &id("s1"), Default::default())),
        "<create_task><name>foo</name><usage_type>scan</usage_type><config id=\"c1\"/><target id=\"t1\"/><scanner id=\"s1\"/></create_task>"
    );
}

#[test]
fn test_create_task_with_optionals() {
    assert_eq!(
        xml(create_task(
            "foo",
            &id("c1"),
            &id("t1"),
            &id("s1"),
            CreateTaskOpts {
                alterable: Some(true),
                hosts_ordering: Some(HostsOrdering::Random),
                schedule_id: Some(id("sched1")),
                alert_ids: vec![id("a1"), id("a2")],
                comment: Some("bar".into()),
                schedule_periods: Some(5),
                observers: vec!["alice".into(), "bob".into()],
                preferences: vec![("k".into(), "v".into())],
            }
        )),
        "<create_task><name>foo</name><usage_type>scan</usage_type><config id=\"c1\"/><target id=\"t1\"/><scanner id=\"s1\"/><comment>bar</comment><alterable>1</alterable><hosts_ordering>random</hosts_ordering><schedule id=\"sched1\"/><schedule_periods>5</schedule_periods><alert id=\"a1\"/><alert id=\"a2\"/><observers><observer>alice</observer><observer>bob</observer></observers><preferences><preference><scanner_name>k</scanner_name><value>v</value></preference></preferences></create_task>"
    );
}

#[test]
fn test_create_agent_group_task() {
    assert_eq!(
        xml(create_agent_group_task(
            "foo",
            &id("ag1"),
            &id("s1"),
            Default::default()
        )),
        "<create_task><name>foo</name><usage_type>scan</usage_type><agent_group id=\"ag1\"/><scanner id=\"s1\"/></create_task>"
    );
}

#[test]
fn test_create_agent_group_task_with_optionals() {
    assert_eq!(
        xml(create_agent_group_task(
            "foo",
            &id("ag1"),
            &id("s1"),
            CreateAgentGroupTaskOpts {
                comment: Some("bar".into()),
                alterable: Some(true),
                schedule_id: Some(id("sched1")),
                alert_ids: vec![id("a1"), id("a2")],
                schedule_periods: Some(5),
                observers: vec!["alice".into(), "bob".into()],
                preferences: vec![("k".into(), "v".into())],
            }
        )),
        "<create_task><name>foo</name><usage_type>scan</usage_type><agent_group id=\"ag1\"/><scanner id=\"s1\"/><comment>bar</comment><alterable>1</alterable><alert id=\"a1\"/><alert id=\"a2\"/><schedule id=\"sched1\"/><schedule_periods>5</schedule_periods><observers><observer>alice</observer><observer>bob</observer></observers><preferences><preference><scanner_name>k</scanner_name><value>v</value></preference></preferences></create_task>"
    );
}

#[test]
fn test_create_agent_group_task_ignores_schedule_periods_without_schedule() {
    assert_eq!(
        xml(create_agent_group_task(
            "foo",
            &id("ag1"),
            &id("s1"),
            CreateAgentGroupTaskOpts {
                schedule_periods: Some(5),
                ..Default::default()
            }
        )),
        "<create_task><name>foo</name><usage_type>scan</usage_type><agent_group id=\"ag1\"/><scanner id=\"s1\"/></create_task>"
    );
}

#[test]
fn test_create_oci_image_target_task() {
    assert_eq!(
        xml(create_oci_image_target_task(
            "foo",
            &id("oci1"),
            &id("s1"),
            Default::default()
        )),
        "<create_task><name>foo</name><usage_type>scan</usage_type><oci_image_target id=\"oci1\"/><scanner id=\"s1\"/></create_task>"
    );
    assert_eq!(
        xml(create_container_image_task(
            "foo",
            &id("oci1"),
            &id("s1"),
            Default::default()
        )),
        "<create_task><name>foo</name><usage_type>scan</usage_type><oci_image_target id=\"oci1\"/><scanner id=\"s1\"/></create_task>"
    );
}

#[test]
fn test_create_oci_image_target_task_with_optionals() {
    assert_eq!(
        xml(create_oci_image_target_task(
            "foo",
            &id("oci1"),
            &id("s1"),
            CreateOciImageTargetTaskOpts {
                comment: Some("bar".into()),
                alterable: Some(true),
                schedule_id: Some(id("sched1")),
                alert_ids: vec![id("a1"), id("a2")],
                schedule_periods: Some(5),
                observers: vec!["alice".into(), "bob".into()],
                preferences: vec![("k".into(), "v".into())],
            }
        )),
        "<create_task><name>foo</name><usage_type>scan</usage_type><oci_image_target id=\"oci1\"/><scanner id=\"s1\"/><comment>bar</comment><alterable>1</alterable><alert id=\"a1\"/><alert id=\"a2\"/><schedule id=\"sched1\"/><schedule_periods>5</schedule_periods><observers><observer>alice</observer><observer>bob</observer></observers><preferences><preference><scanner_name>k</scanner_name><value>v</value></preference></preferences></create_task>"
    );
}

#[test]
fn test_create_oci_image_target_task_ignores_schedule_periods_without_schedule() {
    assert_eq!(
        xml(create_oci_image_target_task(
            "foo",
            &id("oci1"),
            &id("s1"),
            CreateOciImageTargetTaskOpts {
                schedule_periods: Some(5),
                ..Default::default()
            }
        )),
        "<create_task><name>foo</name><usage_type>scan</usage_type><oci_image_target id=\"oci1\"/><scanner id=\"s1\"/></create_task>"
    );
}

#[test]
fn test_task_mutation_and_actions() {
    assert_eq!(
        xml(clone_task(&id("a1"))),
        "<create_task><copy>a1</copy></create_task>"
    );
    assert_eq!(
        xml(clone_audit(&id("a1"))),
        "<create_task><copy>a1</copy></create_task>"
    );
    assert_eq!(
        xml(create_container_task("foo", Some("bar"))),
        "<create_task><name>foo</name><target id=\"0\"/><comment>bar</comment></create_task>"
    );
    assert_eq!(
        xml(create_import_task("foo", Some("bar"))),
        "<create_task><name>foo</name><target id=\"0\"/><comment>bar</comment></create_task>"
    );
    assert_eq!(
        xml(get_task(&id("a1"))),
        "<get_tasks details=\"1\" task_id=\"a1\" usage_type=\"scan\"/>"
    );
    assert_eq!(
        xml(get_audit(&id("a1"))),
        "<get_tasks details=\"1\" task_id=\"a1\" usage_type=\"audit\"/>"
    );
    assert_eq!(
        xml(move_task(&id("a1"), Some(&id("s1")))),
        "<move_task slave_id=\"s1\" task_id=\"a1\"/>"
    );
    assert_eq!(xml(start_task(&id("a1"))), "<start_task task_id=\"a1\"/>");
    assert_eq!(xml(resume_task(&id("a1"))), "<resume_task task_id=\"a1\"/>");
    assert_eq!(xml(stop_task(&id("a1"))), "<stop_task task_id=\"a1\"/>");
}
