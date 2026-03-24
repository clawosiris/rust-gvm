// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::schedules::*;

#[test]
fn test_create_schedule_basic() {
    assert_eq!(
        xml(create_schedule("sched", Default::default())),
        "<create_schedule><name>sched</name></create_schedule>"
    );
}

#[test]
fn test_create_schedule_with_icalendar() {
    let ical = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR";
    let rendered = xml(create_schedule(
        "daily-scan",
        ScheduleOpts {
            comment: Some("run daily".into()),
            icalendar: Some(ical.into()),
            timezone: Some("UTC".into()),
            ..Default::default()
        },
    ));
    assert!(rendered.contains("<name>daily-scan</name>"));
    assert!(rendered.contains("<comment>run daily</comment>"));
    assert!(rendered.contains("<icalendar>BEGIN:VCALENDAR"));
    assert!(rendered.contains("<timezone>UTC</timezone>"));
}

#[test]
fn test_schedule_get_modify_delete() {
    assert_eq!(
        xml(clone_schedule(&id("sc1"))),
        "<create_schedule><copy>sc1</copy></create_schedule>"
    );
    assert_eq!(
        xml(get_schedule(&id("sc1"))),
        "<get_schedules details=\"1\" schedule_id=\"sc1\"/>"
    );
    assert_eq!(
        xml(delete_schedule(&id("sc1"), false)),
        "<delete_schedule schedule_id=\"sc1\" ultimate=\"0\"/>"
    );
}

#[test]
fn test_modify_schedule_with_icalendar() {
    let rendered = xml(modify_schedule(
        &id("sc1"),
        ScheduleOpts {
            name: Some("updated".into()),
            icalendar: Some("BEGIN:VCALENDAR\r\nEND:VCALENDAR".into()),
            timezone: Some("Europe/Berlin".into()),
            ..Default::default()
        },
    ));
    assert!(rendered.contains("schedule_id=\"sc1\""));
    assert!(rendered.contains("<name>updated</name>"));
    assert!(rendered.contains("<icalendar>"));
    assert!(rendered.contains("<timezone>Europe/Berlin</timezone>"));
}
