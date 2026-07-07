// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Task command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::commands::usage_type::UsageType;
use crate::common::{
    add_filter_attrs, add_id_element, add_optional_id_element, add_preferences, add_string_list,
    add_text_element, bool_str, set_optional_bool_attr,
};
use crate::enums::HostsOrdering;
use crate::types::EntityId;

/// Optional fields for `create_task` requests.
#[derive(Debug, Clone, Default)]
pub struct CreateTaskOpts {
    /// Whether the task should be alterable.
    pub alterable: Option<bool>,
    /// Optional task host ordering.
    pub hosts_ordering: Option<HostsOrdering>,
    /// Optional schedule identifier.
    pub schedule_id: Option<EntityId>,
    /// Alert identifiers associated with the request.
    pub alert_ids: Vec<EntityId>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional schedule period count.
    pub schedule_periods: Option<u32>,
    /// Observer names associated with the task.
    pub observers: Vec<String>,
    /// Preference key/value pairs to include.
    pub preferences: Vec<(String, String)>,
}

/// Optional fields for `create_agent_group_task` requests.
#[derive(Debug, Clone, Default)]
pub struct CreateAgentGroupTaskOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Whether the task should be alterable.
    pub alterable: Option<bool>,
    /// Optional schedule identifier.
    pub schedule_id: Option<EntityId>,
    /// Alert identifiers associated with the request.
    pub alert_ids: Vec<EntityId>,
    /// Optional schedule period count.
    pub schedule_periods: Option<u32>,
    /// Observer names associated with the task.
    pub observers: Vec<String>,
    /// Preference key/value pairs to include.
    pub preferences: Vec<(String, String)>,
}

/// Options for `get_tasks` requests.
#[derive(Debug, Clone, Default)]
pub struct GetTasksOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
    /// Whether to limit results to scheduled tasks.
    pub schedules_only: Option<bool>,
    /// Whether pagination should be ignored.
    pub ignore_pagination: Option<bool>,
}

/// Optional fields for `modify_task` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyTaskOpts {
    /// Optional resource name.
    pub name: Option<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Whether the task should be alterable.
    pub alterable: Option<bool>,
    /// Optional task host ordering.
    pub hosts_ordering: Option<HostsOrdering>,
    /// Optional schedule identifier.
    pub schedule_id: Option<EntityId>,
    /// Optional schedule period count.
    pub schedule_periods: Option<u32>,
    /// Optional target identifier.
    pub target_id: Option<EntityId>,
    /// Optional scan configuration identifier.
    pub config_id: Option<EntityId>,
    /// Optional scanner identifier.
    pub scanner_id: Option<EntityId>,
    /// Alert identifiers associated with the request.
    pub alert_ids: Option<Vec<EntityId>>,
    /// Observer names associated with the task.
    pub observers: Vec<String>,
    /// Preference key/value pairs to include.
    pub preferences: Vec<(String, String)>,
}

/// Build a clone request for an existing task.
#[must_use]
pub fn clone_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("create_task").child_with_text("copy", task_id.as_str())
}

/// Build a `create_task` request for an import task.
#[must_use]
pub fn create_import_task(name: &str, comment: Option<&str>) -> impl Request {
    let mut cmd = XmlCommand::new("create_task");
    cmd.add_element_with_text("name", name);
    cmd.add_element("target").set_attribute("id", "0");
    add_text_element(&mut cmd, "comment", comment);
    cmd
}

/// Build a `create_task` request for an import task.
///
/// This is a compatibility alias for [`create_import_task`].
#[must_use]
pub fn create_container_task(name: &str, comment: Option<&str>) -> impl Request {
    create_import_task(name, comment)
}

/// Build a `create_task` request for an agent-group scan task.
#[must_use]
pub fn create_agent_group_task(
    name: &str,
    agent_group_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateAgentGroupTaskOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("create_task");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("usage_type", UsageType::Scan.as_gmp_str());
    add_id_element(&mut cmd, "agent_group", agent_group_id);
    add_id_element(&mut cmd, "scanner", scanner_id);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(alterable) = opts.alterable {
        cmd.add_element_with_text("alterable", bool_str(alterable));
    }
    for alert_id in &opts.alert_ids {
        add_id_element(&mut cmd, "alert", alert_id);
    }
    if let Some(schedule_id) = opts.schedule_id.as_ref() {
        add_id_element(&mut cmd, "schedule", schedule_id);
        if let Some(schedule_periods) = opts.schedule_periods {
            cmd.add_element_with_text("schedule_periods", &schedule_periods.to_string());
        }
    }
    add_string_list(&mut cmd, "observers", "observer", &opts.observers);
    add_preferences(&mut cmd, &opts.preferences);
    cmd
}

/// Build a `create_task` request.
#[must_use]
pub fn create_task(
    name: &str,
    config_id: &EntityId,
    target_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateTaskOpts,
) -> impl Request {
    create_task_with_usage(
        name,
        config_id,
        target_id,
        scanner_id,
        opts,
        UsageType::Scan,
    )
}

fn create_task_with_usage(
    name: &str,
    config_id: &EntityId,
    target_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateTaskOpts,
    usage_type: UsageType,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_task");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("usage_type", usage_type.as_gmp_str());
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

/// Build a `delete_task` request.
#[must_use]
pub fn delete_task(task_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_task")
        .attribute("task_id", task_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

/// Build a `get_tasks` request.
#[must_use]
pub fn get_tasks(opts: GetTasksOpts) -> impl Request {
    get_tasks_with_usage(opts, UsageType::Scan)
}

fn get_tasks_with_usage(opts: GetTasksOpts, usage_type: UsageType) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_tasks").attribute("usage_type", usage_type.as_gmp_str());
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    set_optional_bool_attr(&mut cmd, "schedules_only", opts.schedules_only);
    set_optional_bool_attr(&mut cmd, "ignore_pagination", opts.ignore_pagination);
    cmd
}

/// Build a `get_task` request.
#[must_use]
pub fn get_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("get_tasks")
        .attribute("task_id", task_id.as_str())
        .attribute("usage_type", UsageType::Scan.as_gmp_str())
        .attribute("details", "1")
}

/// Build a `modify_task` request.
#[must_use]
pub fn modify_task(task_id: &EntityId, opts: ModifyTaskOpts) -> impl Request {
    modify_task_with_usage(task_id, opts, None)
}

fn modify_task_with_usage(
    task_id: &EntityId,
    opts: ModifyTaskOpts,
    usage_type: Option<UsageType>,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_task").attribute("task_id", task_id.as_str());
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(usage_type) = usage_type {
        cmd.add_element_with_text("usage_type", usage_type.as_gmp_str());
    }
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

/// Build a `move_task` request.
#[must_use]
pub fn move_task(task_id: &EntityId, slave_id: Option<&EntityId>) -> impl Request {
    let mut cmd = XmlCommand::new("move_task").attribute("task_id", task_id.as_str());
    if let Some(slave_id) = slave_id {
        cmd.set_attribute("slave_id", slave_id.as_str());
    }
    cmd
}

/// Build a `start_task` request.
#[must_use]
pub fn start_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("start_task").attribute("task_id", task_id.as_str())
}

/// Build a `resume_task` request.
#[must_use]
pub fn resume_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("resume_task").attribute("task_id", task_id.as_str())
}

/// Build a `stop_task` request.
#[must_use]
pub fn stop_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("stop_task").attribute("task_id", task_id.as_str())
}

/// Build a `create_task` request for an audit.
#[must_use]
pub fn create_audit(
    name: &str,
    config_id: &EntityId,
    target_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateTaskOpts,
) -> impl Request {
    create_task_with_usage(
        name,
        config_id,
        target_id,
        scanner_id,
        opts,
        UsageType::Audit,
    )
}

/// Build a `get_tasks` request scoped to audits.
#[must_use]
pub fn get_audits(opts: GetTasksOpts) -> impl Request {
    get_tasks_with_usage(opts, UsageType::Audit)
}

/// Build a clone request for an existing audit.
#[must_use]
pub fn clone_audit(task_id: &EntityId) -> impl Request {
    clone_task(task_id)
}

/// Build a `get_tasks` request for a single audit.
#[must_use]
pub fn get_audit(task_id: &EntityId) -> impl Request {
    XmlCommand::new("get_tasks")
        .attribute("task_id", task_id.as_str())
        .attribute("usage_type", UsageType::Audit.as_gmp_str())
        .attribute("details", "1")
}

/// Build a `start_task` request for an audit.
#[must_use]
pub fn start_audit(task_id: &EntityId) -> impl Request {
    start_task(task_id)
}

/// Build a `stop_task` request for an audit.
#[must_use]
pub fn stop_audit(task_id: &EntityId) -> impl Request {
    stop_task(task_id)
}

/// Build a `resume_task` request for an audit.
#[must_use]
pub fn resume_audit(task_id: &EntityId) -> impl Request {
    resume_task(task_id)
}

/// Build a `modify_task` request scoped to audits.
#[must_use]
pub fn modify_audit(task_id: &EntityId, opts: ModifyTaskOpts) -> impl Request {
    modify_task_with_usage(task_id, opts, Some(UsageType::Audit))
}

/// Build a `delete_task` request for an audit.
#[must_use]
pub fn delete_audit(task_id: &EntityId) -> impl Request {
    delete_task(task_id, false)
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
        assert_eq!(
            xml(clone_task(&id("a1"))),
            "<create_task><copy>a1</copy></create_task>"
        );
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
        assert_eq!(
            rendered,
            "<modify_task task_id=\"t1\"><name>foo</name><alert id=\"0\"/></modify_task>"
        );
        assert_eq!(
            xml(move_task(&id("a1"), Some(&id("s1")))),
            "<move_task slave_id=\"s1\" task_id=\"a1\"/>"
        );
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

    #[test]
    fn audit_commands_build_xml() {
        assert!(xml(create_audit(
            "audit",
            &id("c1"),
            &id("t1"),
            &id("s1"),
            CreateTaskOpts::default(),
        ))
        .contains("<usage_type>audit</usage_type>"));
        assert_eq!(
            xml(get_audits(GetTasksOpts::default())),
            "<get_tasks usage_type=\"audit\"/>"
        );
        assert_eq!(
            xml(clone_audit(&id("a1"))),
            "<create_task><copy>a1</copy></create_task>"
        );
        assert_eq!(
            xml(get_audit(&id("a1"))),
            "<get_tasks details=\"1\" task_id=\"a1\" usage_type=\"audit\"/>"
        );
        assert_eq!(
            xml(modify_audit(
                &id("a1"),
                ModifyTaskOpts {
                    comment: Some("updated".into()),
                    ..Default::default()
                }
            )),
            "<modify_task task_id=\"a1\"><comment>updated</comment><usage_type>audit</usage_type></modify_task>"
        );
        assert_eq!(xml(start_audit(&id("a1"))), "<start_task task_id=\"a1\"/>");
        assert_eq!(xml(stop_audit(&id("a1"))), "<stop_task task_id=\"a1\"/>");
        assert_eq!(
            xml(resume_audit(&id("a1"))),
            "<resume_task task_id=\"a1\"/>"
        );
        assert_eq!(
            xml(delete_audit(&id("a1"))),
            "<delete_task task_id=\"a1\" ultimate=\"0\"/>"
        );
    }
}
