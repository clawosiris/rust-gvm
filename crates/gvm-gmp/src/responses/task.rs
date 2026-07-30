// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Task response models.

use gvm_protocol::Response;

use crate::{
    responses::common::{
        count_info, optional_u32, parse_bool, parse_document, parse_entity_id, parse_entity_meta,
        parse_named_entity, status_from_response, ActionResponse, CountInfo, EntityMeta,
        NamedEntity, ParseError, XmlNode,
    },
    EntityId,
};

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Task {
    pub meta: EntityMeta,
    pub status: Option<String>,
    pub progress: Option<i32>,
    pub alterable: Option<bool>,
    pub target: Option<NamedEntity>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub agent_group: Option<NamedEntity>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub oci_image_target: Option<NamedEntity>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub web_application_target: Option<NamedEntity>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub additional_targets: Vec<TaskTargetReference>,
    pub config: Option<NamedEntity>,
    pub scanner: Option<NamedEntity>,
    pub schedule: Option<NamedEntity>,
    pub alerts: Vec<NamedEntity>,
    pub observers: Option<TaskObservers>,
    pub current_report: Option<CurrentReport>,
    pub last_report: Option<LastReport>,
    pub report_count: Option<u32>,
    pub schedule_periods: Option<u32>,
    pub trend: Option<String>,
    pub usage_type: Option<String>,
    pub hosts_ordering: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TaskTargetReference {
    pub kind: String,
    pub entity: NamedEntity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LastReport {
    pub id: EntityId,
    pub timestamp: Option<String>,
    pub scan_start: Option<String>,
    pub scan_end: Option<String>,
    pub result_count: Option<TaskReportResultCount>,
    pub severity: Option<String>,
    pub compliance_count: Option<TaskReportComplianceCount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CurrentReport {
    pub id: EntityId,
    pub timestamp: Option<String>,
    pub scan_start: Option<String>,
    pub scan_end: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TaskReportResultCount {
    pub critical: Option<u32>,
    pub high: Option<u32>,
    pub medium: Option<u32>,
    pub low: Option<u32>,
    pub log: Option<u32>,
    pub false_positive: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TaskReportComplianceCount {
    pub yes: Option<u32>,
    pub no: Option<u32>,
    pub incomplete: Option<u32>,
}

struct TaskReportReference {
    id: EntityId,
    timestamp: Option<String>,
    scan_start: Option<String>,
    scan_end: Option<String>,
    result_count: Option<TaskReportResultCount>,
    severity: Option<String>,
    compliance_count: Option<TaskReportComplianceCount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TaskObservers {
    pub users: Vec<String>,
    pub groups: Vec<NamedEntity>,
    pub roles: Vec<NamedEntity>,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetTasksResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Task>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateTaskResponse {
    pub status: u16,
    pub status_text: String,
    pub id: EntityId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StartTaskResponse {
    pub status: u16,
    pub status_text: String,
    pub report_id: Option<EntityId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResumeTaskResponse {
    pub status: u16,
    pub status_text: String,
    pub report_id: Option<EntityId>,
}

impl Task {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        let target = parse_named_entity(node, "target")?;
        let agent_group = parse_named_entity(node, "agent_group")?;
        let oci_image_target = parse_named_entity(node, "oci_image_target")?;
        let web_application_target = parse_named_entity(node, "web_application_target")?;
        let additional_targets = parse_additional_targets(node)?;
        validate_target_selectors(
            target.as_ref(),
            agent_group.as_ref(),
            oci_image_target.as_ref(),
            web_application_target.as_ref(),
            &additional_targets,
        )?;
        Ok(Self {
            meta: parse_entity_meta(node)?,
            status: node.optional_child_text("status"),
            progress: node
                .optional_child_text("progress")
                .map(|value| {
                    value.parse::<i32>().map_err(|_| ParseError::InvalidValue {
                        field: "progress".to_string(),
                        value,
                    })
                })
                .transpose()?,
            alterable: node
                .optional_child_text("alterable")
                .map(|value| parse_bool(&value, "alterable"))
                .transpose()?,
            target,
            agent_group,
            oci_image_target,
            web_application_target,
            additional_targets,
            config: parse_named_entity(node, "config")?,
            scanner: parse_named_entity(node, "scanner")?,
            schedule: parse_named_entity(node, "schedule")?,
            alerts: node
                .children_named("alert")
                .map(|alert| -> Result<NamedEntity, ParseError> {
                    let id = parse_entity_id(
                        alert
                            .attr("id")
                            .ok_or_else(|| ParseError::MissingElement("alert.id".to_string()))?,
                        "alert.id",
                    )?;
                    let name = alert.required_child_text("name")?;
                    Ok(NamedEntity { id, name })
                })
                .collect::<Result<Vec<_>, _>>()?,
            observers: parse_observers(node)?,
            current_report: parse_current_report(node)?,
            last_report: parse_last_report(node)?,
            report_count: optional_u32(node, "report_count", "report_count")?,
            schedule_periods: optional_u32(node, "schedule_periods", "schedule_periods")?,
            trend: node.optional_child_text("trend"),
            usage_type: node.optional_child_text("usage_type"),
            hosts_ordering: node.optional_child_text("hosts_ordering"),
        })
    }
}

fn parse_additional_targets(node: &XmlNode) -> Result<Vec<TaskTargetReference>, ParseError> {
    node.children
        .iter()
        .filter(|child| {
            child.name.ends_with("_target")
                && !matches!(
                    child.name.as_str(),
                    "oci_image_target" | "web_application_target"
                )
        })
        .map(|child| {
            let raw_id = child
                .attr("id")
                .ok_or_else(|| ParseError::MissingElement(format!("{}.id", child.name)))?;
            let entity = NamedEntity {
                id: parse_entity_id(raw_id, &format!("{}.id", child.name))?,
                name: child.required_child_text("name")?,
            };
            Ok(TaskTargetReference {
                kind: child.name.clone(),
                entity,
            })
        })
        .collect()
}

fn validate_target_selectors(
    target: Option<&NamedEntity>,
    agent_group: Option<&NamedEntity>,
    oci_image_target: Option<&NamedEntity>,
    web_application_target: Option<&NamedEntity>,
    additional_targets: &[TaskTargetReference],
) -> Result<(), ParseError> {
    let mut selectors = Vec::new();
    if target.is_some() {
        selectors.push("target");
    }
    if agent_group.is_some() {
        selectors.push("agent_group");
    }
    if oci_image_target.is_some() {
        selectors.push("oci_image_target");
    }
    if web_application_target.is_some() {
        selectors.push("web_application_target");
    }
    selectors.extend(additional_targets.iter().map(|target| target.kind.as_str()));
    if selectors.len() > 1 {
        return Err(ParseError::InvalidValue {
            field: "task.target_selector".to_string(),
            value: selectors.join(", "),
        });
    }
    Ok(())
}

impl GetTasksResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("task")
            .map(Task::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "task_count")?,
        })
    }
}

impl CreateTaskResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let id = parse_entity_id(
            root.attr("id")
                .ok_or_else(|| ParseError::MissingElement("id".to_string()))?,
            "id",
        )?;
        Ok(Self {
            status,
            status_text,
            id,
        })
    }
}

impl StartTaskResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text, report_id) = parse_task_action_response(response)?;
        Ok(Self {
            status,
            status_text,
            report_id,
        })
    }
}

impl ResumeTaskResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text, report_id) = parse_task_action_response(response)?;
        Ok(Self {
            status,
            status_text,
            report_id,
        })
    }
}

fn parse_task_action_response(
    response: &Response,
) -> Result<(u16, String, Option<EntityId>), ParseError> {
    let (status, status_text) = status_from_response(response)?;
    let root = parse_document(response.data())?;
    let report_id = root
        .optional_child_text("report_id")
        .map(|value| parse_entity_id(&value, "report_id"))
        .transpose()?;
    Ok((status, status_text, report_id))
}

fn parse_current_report(node: &XmlNode) -> Result<Option<CurrentReport>, ParseError> {
    parse_report_reference(node, "current_report").map(|report| {
        report.map(|report| CurrentReport {
            id: report.id,
            timestamp: report.timestamp,
            scan_start: report.scan_start,
            scan_end: report.scan_end,
        })
    })
}

fn parse_last_report(node: &XmlNode) -> Result<Option<LastReport>, ParseError> {
    parse_report_reference(node, "last_report").map(|report| {
        report.map(|report| LastReport {
            id: report.id,
            timestamp: report.timestamp,
            scan_start: report.scan_start,
            scan_end: report.scan_end,
            result_count: report.result_count,
            severity: report.severity,
            compliance_count: report.compliance_count,
        })
    })
}

fn parse_report_reference(
    node: &XmlNode,
    field: &str,
) -> Result<Option<TaskReportReference>, ParseError> {
    node.child(field)
        .and_then(|report_wrapper| report_wrapper.child("report"))
        .map(|report| -> Result<TaskReportReference, ParseError> {
            Ok(TaskReportReference {
                id: parse_entity_id(
                    report
                        .attr("id")
                        .ok_or_else(|| ParseError::MissingElement(format!("{field}.report.id")))?,
                    &format!("{field}.report.id"),
                )?,
                timestamp: report.optional_child_text("timestamp"),
                scan_start: report.optional_child_text("scan_start"),
                scan_end: report.optional_child_text("scan_end"),
                result_count: report
                    .child("result_count")
                    .map(parse_task_report_result_count)
                    .transpose()?,
                severity: report.optional_child_text("severity"),
                compliance_count: report
                    .child("compliance_count")
                    .map(parse_task_report_compliance_count)
                    .transpose()?,
            })
        })
        .transpose()
}

fn parse_task_report_result_count(node: &XmlNode) -> Result<TaskReportResultCount, ParseError> {
    Ok(TaskReportResultCount {
        critical: optional_u32(node, "critical", "last_report.result_count.critical")?,
        high: optional_u32_with_alias(node, "high", "hole", "last_report.result_count.high")?,
        medium: optional_u32_with_alias(
            node,
            "medium",
            "warning",
            "last_report.result_count.medium",
        )?,
        low: optional_u32_with_alias(node, "low", "info", "last_report.result_count.low")?,
        log: optional_u32(node, "log", "last_report.result_count.log")?,
        false_positive: optional_u32(
            node,
            "false_positive",
            "last_report.result_count.false_positive",
        )?,
    })
}

fn optional_u32_with_alias(
    node: &XmlNode,
    canonical: &str,
    alias: &str,
    field: &str,
) -> Result<Option<u32>, ParseError> {
    if node.child(canonical).is_some() {
        optional_u32(node, canonical, field)
    } else {
        optional_u32(node, alias, field)
    }
}

fn parse_task_report_compliance_count(
    node: &XmlNode,
) -> Result<TaskReportComplianceCount, ParseError> {
    Ok(TaskReportComplianceCount {
        yes: optional_u32(node, "yes", "last_report.compliance_count.yes")?,
        no: optional_u32(node, "no", "last_report.compliance_count.no")?,
        incomplete: optional_u32(
            node,
            "incomplete",
            "last_report.compliance_count.incomplete",
        )?,
    })
}

fn parse_observers(node: &XmlNode) -> Result<Option<TaskObservers>, ParseError> {
    node.child("observers")
        .map(|observers| {
            Ok(TaskObservers {
                users: parse_user_list(&observers.text),
                groups: parse_named_children(observers, "group", "observers.group")?,
                roles: parse_named_children(observers, "role", "observers.role")?,
            })
        })
        .transpose()
}

fn parse_user_list(value: &str) -> Vec<String> {
    value
        .split(|separator: char| separator.is_whitespace() || separator == ',')
        .filter_map(non_empty_text)
        .collect()
}

fn non_empty_text(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn parse_named_children(
    node: &XmlNode,
    child_name: &str,
    field: &str,
) -> Result<Vec<NamedEntity>, ParseError> {
    node.children_named(child_name)
        .map(|child| -> Result<NamedEntity, ParseError> {
            let id = parse_entity_id(
                child
                    .attr("id")
                    .ok_or_else(|| ParseError::MissingElement(format!("{field}.id")))?,
                &format!("{field}.id"),
            )?;
            let name = child.required_child_text("name")?;
            Ok(NamedEntity { id, name })
        })
        .collect()
}

pub type StopTaskResponse = ActionResponse;
pub type ModifyTaskResponse = ActionResponse;
pub type DeleteTaskResponse = ActionResponse;
pub type MoveTaskResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    const CURRENT_GVMD_TASKS_RESPONSE: &str = r#"<get_tasks_response status="200" status_text="OK">
            <task id="task-1">
                <owner><name>admin</name></owner>
                <name>Discovery Scan</name>
                <comment>Network scan</comment>
                <creation_time>2026-01-01T00:00:00Z</creation_time>
                <modification_time>2026-01-02T00:00:00Z</modification_time>
                <writable>1</writable>
                <in_use>1</in_use>
                <status>Done</status>
                <progress>100</progress>
                <alterable>1</alterable>
                <target id="t-1"><name>Local Net</name></target>
                <config id="cfg-1"><name>Full and fast</name></config>
                <scanner id="sc-1"><name>Default</name></scanner>
                <schedule id="sched-1"><name>Weekly</name></schedule>
                <alert id="alert-1"><name>Email</name></alert>
                <alert id="alert-2"><name>Ticket</name></alert>
                <observers>
                    alice bob carol
                    <group id="grp-1"><name>Auditors</name></group>
                    <role id="role-1"><name>Observer</name></role>
                </observers>
                <current_report>
                    <report id="rpt-current-1">
                        <timestamp>2026-01-15T10:00:00Z</timestamp>
                        <scan_start>2026-01-15T10:00:01Z</scan_start>
                        <scan_end></scan_end>
                    </report>
                </current_report>
                <last_report>
                    <report id="rpt-1">
                        <timestamp>2026-01-15T10:30:00Z</timestamp>
                        <scan_start>2026-01-15T10:00:01Z</scan_start>
                        <scan_end>2026-01-15T10:29:59Z</scan_end>
                        <result_count>
                            <critical>2</critical>
                            <hole deprecated="1">3</hole>
                            <high>3</high>
                            <info deprecated="1">5</info>
                            <low>5</low>
                            <log>7</log>
                            <warning deprecated="1">11</warning>
                            <medium>11</medium>
                            <false_positive>13</false_positive>
                        </result_count>
                        <severity>8.8</severity>
                    </report>
                </last_report>
                <report_count>5</report_count>
                <schedule_periods>3</schedule_periods>
                <trend>up</trend>
                <usage_type>scan</usage_type>
                <hosts_ordering>sequential</hosts_ordering>
            </task>
            <task id="task-2">
                <name>Audit Task</name>
                <status>Done</status>
                <progress>42</progress>
                <usage_type>audit</usage_type>
                <last_report>
                    <report id="audit-report-1">
                        <timestamp>2026-01-16T12:00:00Z</timestamp>
                        <scan_start>2026-01-16T11:00:00Z</scan_start>
                        <scan_end>2026-01-16T12:00:00Z</scan_end>
                        <compliance_count>
                            <yes>17</yes>
                            <no>19</no>
                            <incomplete>23</incomplete>
                        </compliance_count>
                    </report>
                </last_report>
            </task>
            <task_count>2<filtered>2</filtered><page>1</page></task_count>
        </get_tasks_response>"#;

    #[test]
    fn parses_multiple_tasks() {
        let response = Response::from(CURRENT_GVMD_TASKS_RESPONSE);

        let parsed = GetTasksResponse::from_response(&response).expect("tasks parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].status.as_deref(), Some("Done"));
        assert_eq!(parsed.items[0].progress, Some(100));
        assert_eq!(parsed.items[0].alterable, Some(true));
        assert_eq!(
            parsed.items[0]
                .target
                .as_ref()
                .map(|target| target.id.as_str()),
            Some("t-1")
        );
        assert_eq!(parsed.items[0].alerts.len(), 2);
        let observers = parsed.items[0].observers.as_ref().expect("observers parse");
        assert_eq!(
            observers
                .users
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["alice", "bob", "carol"]
        );
        assert_eq!(observers.groups[0].id.as_str(), "grp-1");
        assert_eq!(observers.roles[0].id.as_str(), "role-1");
        let current = parsed.items[0]
            .current_report
            .as_ref()
            .expect("current report");
        assert_eq!(current.id.as_str(), "rpt-current-1");
        assert_eq!(current.scan_start.as_deref(), Some("2026-01-15T10:00:01Z"));
        assert_eq!(current.scan_end, None);
        let last = parsed.items[0].last_report.as_ref().expect("last report");
        assert_eq!(last.id.as_str(), "rpt-1");
        assert_eq!(last.scan_end.as_deref(), Some("2026-01-15T10:29:59Z"));
        assert_eq!(last.severity.as_deref(), Some("8.8"));
        assert_eq!(
            last.result_count,
            Some(TaskReportResultCount {
                critical: Some(2),
                high: Some(3),
                medium: Some(11),
                low: Some(5),
                log: Some(7),
                false_positive: Some(13),
            })
        );
        assert_eq!(parsed.items[0].schedule_periods, Some(3));
        assert_eq!(parsed.items[1].progress, Some(42));
        assert_eq!(
            parsed.items[1]
                .last_report
                .as_ref()
                .and_then(|report| report.compliance_count.clone()),
            Some(TaskReportComplianceCount {
                yes: Some(17),
                no: Some(19),
                incomplete: Some(23),
            })
        );
    }

    #[test]
    fn parses_specialized_future_and_targetless_tasks() {
        let response = Response::from(
            r#"<get_tasks_response status="200" status_text="OK">
                <task id="task-agent">
                    <name>Agent task</name>
                    <target id=""><name></name></target>
                    <agent_group id="group-1"><name>Agents</name></agent_group>
                </task>
                <task id="task-oci">
                    <name>OCI task</name>
                    <target id=""><name></name></target>
                    <oci_image_target id="oci-1"><name>Container</name></oci_image_target>
                </task>
                <task id="task-web">
                    <name>Web task</name>
                    <target id=""><name></name></target>
                    <web_application_target id="web-1"><name>Web app</name></web_application_target>
                </task>
                <task id="task-import">
                    <name>Import task</name>
                    <target id=""><name></name></target>
                </task>
                <task id="task-future">
                    <name>Future task</name>
                    <cloud_target id="cloud-1"><name>Cloud</name></cloud_target>
                </task>
                <task_count>5<filtered>5</filtered></task_count>
            </get_tasks_response>"#,
        );

        let parsed = GetTasksResponse::from_response(&response).expect("task variants parse");

        assert_eq!(
            parsed.items[0]
                .agent_group
                .as_ref()
                .map(|target| target.id.as_str()),
            Some("group-1")
        );
        assert_eq!(parsed.items[0].target, None);
        assert_eq!(
            parsed.items[1]
                .oci_image_target
                .as_ref()
                .map(|target| target.id.as_str()),
            Some("oci-1")
        );
        assert_eq!(
            parsed.items[2]
                .web_application_target
                .as_ref()
                .map(|target| target.id.as_str()),
            Some("web-1")
        );
        assert_eq!(parsed.items[3].target, None);
        assert!(parsed.items[3].additional_targets.is_empty());
        assert_eq!(parsed.items[4].additional_targets.len(), 1);
        assert_eq!(parsed.items[4].additional_targets[0].kind, "cloud_target");
        assert_eq!(
            parsed.items[4].additional_targets[0].entity.id.as_str(),
            "cloud-1"
        );
    }

    #[test]
    fn rejects_tasks_with_multiple_target_selectors() {
        let response = Response::from(
            r#"<get_tasks_response status="200" status_text="OK">
                <task id="task-invalid">
                    <name>Invalid task</name>
                    <target id="target-1"><name>Classic</name></target>
                    <agent_group id="group-1"><name>Agents</name></agent_group>
                </task>
            </get_tasks_response>"#,
        );

        let error = GetTasksResponse::from_response(&response).expect_err("multiple targets fail");

        assert!(matches!(
            error,
            ParseError::InvalidValue { field, value }
                if field == "task.target_selector" && value == "target, agent_group"
        ));
    }

    #[test]
    fn parses_empty_tasks() {
        let response = Response::from(
            r#"<get_tasks_response status="200" status_text="OK"><task_count>0<filtered>0</filtered></task_count></get_tasks_response>"#,
        );

        let parsed = GetTasksResponse::from_response(&response).expect("tasks parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_task_response() {
        let response = Response::from(
            r#"<create_task_response status="201" status_text="OK, resource created" id="task-1"/>"#,
        );

        let parsed = CreateTaskResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "task-1");
    }

    #[test]
    fn parses_start_task_response() {
        let response = Response::from(
            r#"<start_task_response status="202" status_text="OK, request submitted"><report_id>rpt-new-1</report_id></start_task_response>"#,
        );

        let parsed = StartTaskResponse::from_response(&response).expect("start parses");

        assert_eq!(parsed.status, 202);
        assert_eq!(
            parsed.report_id.as_ref().map(EntityId::as_str),
            Some("rpt-new-1")
        );
    }

    #[test]
    fn parses_resume_task_response() {
        let response = Response::from(
            r#"<resume_task_response status="202" status_text="OK, request submitted"><report_id>rpt-new-2</report_id></resume_task_response>"#,
        );

        let parsed = ResumeTaskResponse::from_response(&response).expect("resume parses");

        assert_eq!(parsed.status, 202);
        assert_eq!(
            parsed.report_id.as_ref().map(EntityId::as_str),
            Some("rpt-new-2")
        );
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_tasks_response status="400" status_text="Bad request"/>"#);

        let error = GetTasksResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }

    #[test]
    fn parses_missing_optional_task_fields() {
        let response = Response::from(
            r#"<get_tasks_response status="200" status_text="OK">
                <task id="task-1">
                    <name>Only Required</name>
                </task>
            </get_tasks_response>"#,
        );

        let parsed = GetTasksResponse::from_response(&response).expect("tasks parse");
        let task = &parsed.items[0];

        assert_eq!(task.meta.comment, None);
        assert_eq!(task.status, None);
        assert_eq!(task.progress, None);
        assert_eq!(task.alterable, None);
        assert!(task.alerts.is_empty());
        assert_eq!(task.observers, None);
        assert_eq!(task.current_report, None);
        assert_eq!(task.last_report, None);
        assert_eq!(task.report_count, None);
        assert_eq!(task.schedule_periods, None);
        assert!(!task.meta.in_use);
        assert!(!task.meta.writable);
    }

    #[test]
    fn treats_empty_schedule_id_as_absent() {
        let response = Response::from(
            r#"<get_tasks_response status="200" status_text="OK">
                <task id="38ea4c04-fc59-4d58-9a89-3acd40587ce5">
                    <name>Discovery task</name>
                    <status>New</status>
                    <schedule id=""><name></name></schedule>
                </task>
                <task_count>1<filtered>1</filtered></task_count>
            </get_tasks_response>"#,
        );

        let parsed = GetTasksResponse::from_response(&response).expect("tasks parse");

        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.items[0].schedule, None);
    }

    #[test]
    fn rejects_invalid_non_empty_schedule_id() {
        let response = Response::from(
            r#"<get_tasks_response status="200" status_text="OK">
                <task id="task-1">
                    <name>Discovery task</name>
                    <schedule id="not valid"><name>Weekly</name></schedule>
                </task>
            </get_tasks_response>"#,
        );

        let error = GetTasksResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::InvalidValue { field, value }
                if field == "schedule.id" && value == "not valid"
        ));
    }

    #[test]
    fn parses_deprecated_task_result_aliases_without_double_counting() {
        let response = Response::from(
            r#"<get_tasks_response status="200" status_text="OK">
                <task id="task-1">
                    <name>Legacy buckets</name>
                    <last_report>
                        <report id="report-1">
                            <result_count>
                                <hole>3</hole>
                                <info>5</info>
                                <warning>11</warning>
                            </result_count>
                        </report>
                    </last_report>
                </task>
            </get_tasks_response>"#,
        );

        let parsed = GetTasksResponse::from_response(&response).expect("aliases parse");
        let count = parsed.items[0]
            .last_report
            .as_ref()
            .and_then(|report| report.result_count.as_ref())
            .expect("result count");

        assert_eq!(count.high, Some(3));
        assert_eq!(count.low, Some(5));
        assert_eq!(count.medium, Some(11));
    }

    #[test]
    fn rejects_invalid_task_report_counts() {
        let response = Response::from(
            r#"<get_tasks_response status="200" status_text="OK">
                <task id="task-1">
                    <name>Invalid count</name>
                    <last_report>
                        <report id="report-1">
                            <result_count><high>many</high></result_count>
                        </report>
                    </last_report>
                </task>
            </get_tasks_response>"#,
        );

        let error = GetTasksResponse::from_response(&response).expect_err("count must fail");
        assert!(matches!(error, ParseError::InvalidValue { field, value }
                if field == "last_report.result_count.high" && value == "many"));
    }
}
