// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Schedule response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_document, parse_entity_id, parse_entity_meta, status_from_response,
    ActionResponse, CountInfo, EntityMeta, ParseError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Schedule {
    pub meta: EntityMeta,
    pub icalendar: Option<String>,
    pub timezone: Option<String>,
    pub duration: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetSchedulesResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Schedule>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateScheduleResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl Schedule {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            icalendar: node.optional_child_text("icalendar"),
            timezone: node.optional_child_text("timezone"),
            duration: node.optional_child_text("duration"),
        })
    }
}

impl GetSchedulesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("schedule")
            .map(Schedule::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "schedule_count")?,
        })
    }
}

impl CreateScheduleResponse {
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

pub type ModifyScheduleResponse = ActionResponse;
pub type DeleteScheduleResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_schedules() {
        let response = Response::from(
            r#"<get_schedules_response status="200" status_text="OK">
                <schedule id="s-1">
                    <owner><name>admin</name></owner>
                    <name>Schedule One</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <icalendar>BEGIN:VCALENDAR&#10;END:VCALENDAR</icalendar>
                    <timezone>UTC</timezone>
                    <duration>3600</duration>
                </schedule>
                <schedule id="s-2">
                    <name>Schedule Two</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                </schedule>
                <schedule_count>2<filtered>2</filtered><page>1</page></schedule_count>
            </get_schedules_response>"#,
        );

        let parsed = GetSchedulesResponse::from_response(&response).expect("schedules parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].timezone.as_deref(), Some("UTC"));
        assert_eq!(parsed.items[0].duration.as_deref(), Some("3600"));
        assert!(parsed.items[1].meta.in_use);
    }

    #[test]
    fn parses_empty_schedules() {
        let response = Response::from(
            r#"<get_schedules_response status="200" status_text="OK"><schedule_count>0<filtered>0</filtered></schedule_count></get_schedules_response>"#,
        );

        let parsed = GetSchedulesResponse::from_response(&response).expect("schedules parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_schedule_response() {
        let response = Response::from(
            r#"<create_schedule_response status="201" status_text="OK, resource created" id="s-1"/>"#,
        );

        let parsed = CreateScheduleResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "s-1");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_schedules_response status="400" status_text="Bad request"/>"#);

        let error = GetSchedulesResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }

    #[test]
    fn parses_missing_optional_schedule_fields() {
        let response = Response::from(
            r#"<get_schedules_response status="200" status_text="OK">
                <schedule id="s-1">
                    <name>Only Required</name>
                </schedule>
            </get_schedules_response>"#,
        );

        let parsed = GetSchedulesResponse::from_response(&response).expect("schedules parse");
        let schedule = &parsed.items[0];

        assert_eq!(schedule.meta.comment, None);
        assert_eq!(schedule.icalendar, None);
        assert_eq!(schedule.timezone, None);
        assert_eq!(schedule.duration, None);
    }
}
