// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Task response models.

use gvm_protocol::Response;

use crate::{
    responses::common::{
        count_info, optional_u32, parse_document, parse_entity_id, parse_entity_meta,
        parse_named_entity, status_from_response, ActionResponse, CountInfo, EntityMeta,
        NamedEntity, ParseError,
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
    pub target: Option<NamedEntity>,
    pub config: Option<NamedEntity>,
    pub scanner: Option<NamedEntity>,
    pub schedule: Option<NamedEntity>,
    pub alerts: Vec<NamedEntity>,
    pub last_report: Option<LastReport>,
    pub report_count: Option<u32>,
    pub trend: Option<String>,
    pub usage_type: Option<String>,
    pub hosts_ordering: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LastReport {
    pub id: EntityId,
    pub timestamp: Option<String>,
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

impl Task {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
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
            target: parse_named_entity(node, "target")?,
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
            last_report: node
                .child("last_report")
                .and_then(|last_report| last_report.child("report"))
                .map(|report| -> Result<LastReport, ParseError> {
                    Ok(LastReport {
                        id: parse_entity_id(
                            report.attr("id").ok_or_else(|| {
                                ParseError::MissingElement("last_report.report.id".to_string())
                            })?,
                            "last_report.report.id",
                        )?,
                        timestamp: report.optional_child_text("timestamp"),
                    })
                })
                .transpose()?,
            report_count: optional_u32(node, "report_count", "report_count")?,
            trend: node.optional_child_text("trend"),
            usage_type: node.optional_child_text("usage_type"),
            hosts_ordering: node.optional_child_text("hosts_ordering"),
        })
    }
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
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let report_id = root
            .optional_child_text("report_id")
            .map(|value| parse_entity_id(&value, "report_id"))
            .transpose()?;
        Ok(Self {
            status,
            status_text,
            report_id,
        })
    }
}

pub type StopTaskResponse = ActionResponse;
pub type ResumeTaskResponse = ActionResponse;
pub type ModifyTaskResponse = ActionResponse;
pub type DeleteTaskResponse = ActionResponse;
pub type MoveTaskResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_tasks() {
        let response = Response::from(
            r#"<get_tasks_response status="200" status_text="OK">
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
                    <target id="t-1"><name>Local Net</name></target>
                    <config id="cfg-1"><name>Full and fast</name></config>
                    <scanner id="sc-1"><name>Default</name></scanner>
                    <schedule id="sched-1"><name>Weekly</name></schedule>
                    <alert id="alert-1"><name>Email</name></alert>
                    <alert id="alert-2"><name>Ticket</name></alert>
                    <last_report>
                        <report id="rpt-1">
                            <timestamp>2026-01-15T10:30:00Z</timestamp>
                        </report>
                    </last_report>
                    <report_count>5</report_count>
                    <trend>up</trend>
                    <usage_type>scan</usage_type>
                    <hosts_ordering>sequential</hosts_ordering>
                </task>
                <task id="task-2">
                    <name>Running Task</name>
                    <status>Running</status>
                    <progress>42</progress>
                </task>
                <task_count>2<filtered>2</filtered><page>1</page></task_count>
            </get_tasks_response>"#,
        );

        let parsed = GetTasksResponse::from_response(&response).expect("tasks parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].status.as_deref(), Some("Done"));
        assert_eq!(parsed.items[0].progress, Some(100));
        assert_eq!(parsed.items[0].alerts.len(), 2);
        assert_eq!(
            parsed.items[0]
                .last_report
                .as_ref()
                .map(|report| report.id.as_str()),
            Some("rpt-1")
        );
        assert_eq!(parsed.items[1].progress, Some(42));
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
        assert!(task.alerts.is_empty());
        assert_eq!(task.last_report, None);
        assert_eq!(task.report_count, None);
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
}
