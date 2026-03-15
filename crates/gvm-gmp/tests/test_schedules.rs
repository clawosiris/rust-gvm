mod common;

use common::{id, xml};
use gvm_gmp::commands::schedules::*;

#[test]
fn test_create_schedule_basic() {
    assert_eq!(xml(create_schedule("sched", Default::default())), "<create_schedule><name>sched</name></create_schedule>");
}

#[test]
fn test_create_schedule_with_optionals() {
    assert_eq!(
        xml(create_schedule(
            "sched",
            ScheduleOpts {
                comment: Some("c".into()),
                first_time: Some("2026-03-15T10:00:00Z".into()),
                period: Some("3600".into()),
                timezone: Some("UTC".into()),
            }
        )),
        "<create_schedule><name>sched</name><comment>c</comment><first_time>2026-03-15T10:00:00Z</first_time><period>3600</period><timezone>UTC</timezone></create_schedule>"
    );
}

#[test]
fn test_schedule_get_modify_delete() {
    assert_eq!(xml(clone_schedule(&id("sc1"))), "<create_schedule><copy>sc1</copy></create_schedule>");
    assert_eq!(xml(get_schedule(&id("sc1"))), "<get_schedules details=\"1\" schedule_id=\"sc1\"/>");
    assert_eq!(xml(delete_schedule(&id("sc1"), false)), "<delete_schedule schedule_id=\"sc1\" ultimate=\"0\"/>");
}

