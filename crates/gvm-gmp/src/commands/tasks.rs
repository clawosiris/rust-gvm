use gvm_protocol::{Request, XmlCommand};

use crate::common::{
    add_filter_attrs, add_id_element, add_optional_id_element, add_preferences, add_text_element,
    add_string_list, bool_str, set_optional_bool_attr,
};
use crate::enums::HostsOrdering;
use crate::types::EntityId;

#[derive(Debug, Clone, Default)]
pub struct CreateTaskOpts {
    pub alterable: Option<bool>,
    pub hosts_ordering: Option<HostsOrdering>,
    pub schedule_id: Option<EntityId>,
    pub alert_ids: Vec<EntityId>,
    pub comment: Option<String>,
    pub schedule_periods: Option<u32>,
    pub observers: Vec<String>,
    pub preferences: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default)]
pub struct GetTasksOpts {
    pub filter_string: Option<String>,
    pub filter_id: Option<EntityId>,
    pub trash: Option<bool>,
    pub details: Option<bool>,
    pub schedules_only: Option<bool>,
    pub ignore_pagination: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct ModifyTaskOpts {
    pub name: Option<String>,
    pub comment: Option<String>,
    pub alterable: Option<bool>,
    pub hosts_ordering: Option<HostsOrdering>,
    pub schedule_id: Option<EntityId>,
    pub schedule_periods: Option<u32>,
    pub target_id: Option<EntityId>,
    pub config_id: Option<EntityId>,
    pub scanner_id: Option<EntityId>,
    pub alert_ids: Option<Vec<EntityId>>,
    pub observers: Vec<String>,
    pub preferences: Vec<(String, String)>,
}

pub fn clone_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("create_task").child_with_text("copy", task_id.as_str())
}

pub fn create_container_task(name: &str, comment: Option<&str>) -> impl Request {
    let mut cmd = XmlCommand::new("create_task");
    cmd.add_element_with_text("name", name);
    add_text_element(&mut cmd, "comment", comment);
    cmd.add_element("target").set_attribute("id", "0");
    cmd
}

pub fn create_task(
    name: &str,
    config_id: &EntityId,
    target_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateTaskOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("create_task");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("usage_type", "scan");
    add_id_element(&mut cmd, "config", config_id);
    add_id_element(&mut cmd, "target", target_id);
    add_id_element(&mut cmd, "scanner", scanner_id);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(alterable) = opts.alterable {
        cmd.add_element_with_text("alterable", bool_str(alterable));
    }
    if let Some(hosts_ordering) = opts.hosts_ordering {
        cmd.add_element_with_text("hosts_ordering", hosts_ordering.as_gmp_str());
    }
    add_optional_id_element(&mut cmd, "schedule", opts.schedule_id.as_ref());
    if let Some(schedule_periods) = opts.schedule_periods {
        cmd.add_element_with_text("schedule_periods", &schedule_periods.to_string());
    }
    for alert_id in &opts.alert_ids {
        add_id_element(&mut cmd, "alert", alert_id);
    }
    add_string_list(&mut cmd, "observers", "observer", &opts.observers);
    add_preferences(&mut cmd, &opts.preferences);
    cmd
}

pub fn delete_task(task_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_task")
        .attribute("task_id", task_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

pub fn get_tasks(opts: GetTasksOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_tasks").attribute("usage_type", "scan");
    add_filter_attrs(&mut cmd, opts.filter_string.as_deref(), opts.filter_id.as_ref());
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    set_optional_bool_attr(&mut cmd, "schedules_only", opts.schedules_only);
    set_optional_bool_attr(&mut cmd, "ignore_pagination", opts.ignore_pagination);
    cmd
}

pub fn get_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("get_tasks")
        .attribute("task_id", task_id.as_str())
        .attribute("usage_type", "scan")
        .attribute("details", "1")
}

pub fn modify_task(task_id: &EntityId, opts: ModifyTaskOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_task").attribute("task_id", task_id.as_str());
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(alterable) = opts.alterable {
        cmd.add_element_with_text("alterable", bool_str(alterable));
    }
    if let Some(hosts_ordering) = opts.hosts_ordering {
        cmd.add_element_with_text("hosts_ordering", hosts_ordering.as_gmp_str());
    }
    add_optional_id_element(&mut cmd, "schedule", opts.schedule_id.as_ref());
    if let Some(schedule_periods) = opts.schedule_periods {
        cmd.add_element_with_text("schedule_periods", &schedule_periods.to_string());
    }
    add_optional_id_element(&mut cmd, "target", opts.target_id.as_ref());
    add_optional_id_element(&mut cmd, "config", opts.config_id.as_ref());
    add_optional_id_element(&mut cmd, "scanner", opts.scanner_id.as_ref());
    if let Some(alert_ids) = opts.alert_ids.as_ref() {
        if alert_ids.is_empty() {
            cmd.add_element("alert").set_attribute("id", "0");
        } else {
            for alert_id in alert_ids {
                add_id_element(&mut cmd, "alert", alert_id);
            }
        }
    }
    add_string_list(&mut cmd, "observers", "observer", &opts.observers);
    add_preferences(&mut cmd, &opts.preferences);
    cmd
}

pub fn move_task(task_id: &EntityId, slave_id: Option<&EntityId>) -> impl Request {
    let mut cmd = XmlCommand::new("move_task").attribute("task_id", task_id.as_str());
    if let Some(slave_id) = slave_id {
        cmd.set_attribute("slave_id", slave_id.as_str());
    }
    cmd
}

pub fn start_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("start_task").attribute("task_id", task_id.as_str())
}

pub fn resume_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("resume_task").attribute("task_id", task_id.as_str())
}

pub fn stop_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("stop_task").attribute("task_id", task_id.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;
    use crate::enums::HostsOrdering;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn clone_task_builds_copy_xml() {
        assert_eq!(xml(clone_task(&id("a1"))), "<create_task><copy>a1</copy></create_task>");
    }

    #[test]
    fn create_task_builds_full_xml() {
        let rendered = xml(create_task(
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
            },
        ));
        assert!(rendered.contains("<usage_type>scan</usage_type>"));
        assert!(rendered.contains("<config id=\"c1\"/>"));
        assert!(rendered.contains("<hosts_ordering>random</hosts_ordering>"));
        assert!(rendered.contains("<schedule id=\"sched1\"/>"));
        assert!(rendered.contains("<alert id=\"a1\"/>"));
        assert!(rendered.contains("<observer>alice</observer>"));
        assert!(rendered.contains("<scanner_name>k</scanner_name><value>v</value>"));
    }

    #[test]
    fn get_and_delete_task_commands_build_attributes() {
        assert_eq!(
            xml(get_task(&id("a1"))),
            "<get_tasks details=\"1\" task_id=\"a1\" usage_type=\"scan\"/>"
        );
        assert_eq!(
            xml(delete_task(&id("a1"), true)),
            "<delete_task task_id=\"a1\" ultimate=\"1\"/>"
        );
    }

    #[test]
    fn modify_and_action_commands_build_xml() {
        let rendered = xml(modify_task(
            &id("t1"),
            ModifyTaskOpts {
                name: Some("foo".into()),
                alert_ids: Some(Vec::new()),
                ..Default::default()
            },
        ));
        assert_eq!(rendered, "<modify_task task_id=\"t1\"><name>foo</name><alert id=\"0\"/></modify_task>");
        assert_eq!(xml(move_task(&id("a1"), Some(&id("s1")))), "<move_task slave_id=\"s1\" task_id=\"a1\"/>");
        assert_eq!(xml(start_task(&id("a1"))), "<start_task task_id=\"a1\"/>");
        assert_eq!(xml(resume_task(&id("a1"))), "<resume_task task_id=\"a1\"/>");
        assert_eq!(xml(stop_task(&id("a1"))), "<stop_task task_id=\"a1\"/>");
    }

    #[test]
    fn get_tasks_builds_optional_attributes() {
        let rendered = xml(get_tasks(GetTasksOpts {
            filter_string: Some("name=foo".into()),
            filter_id: Some(id("f1")),
            trash: Some(true),
            details: Some(true),
            schedules_only: Some(true),
            ignore_pagination: Some(true),
        }));
        assert!(rendered.contains("usage_type=\"scan\""));
        assert!(rendered.contains("filter=\"name=foo\""));
        assert!(rendered.contains("filt_id=\"f1\""));
        assert!(rendered.contains("trash=\"1\""));
        assert!(rendered.contains("details=\"1\""));
        assert!(rendered.contains("schedules_only=\"1\""));
        assert!(rendered.contains("ignore_pagination=\"1\""));
    }
}
