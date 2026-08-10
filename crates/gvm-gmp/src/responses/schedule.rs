// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Schedule response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, optional_u32, parse_document, parse_entity_id, parse_entity_meta,
    status_from_response, ActionResponse, CountInfo, EntityMeta, ParseError,
};
use crate::schedule::{parse_icalendar_with_timezone, ScheduleObservation, ScheduleTimestamp};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Schedule {
    pub meta: EntityMeta,
    /// Raw iCalendar payload retained for protocol-level compatibility.
    pub icalendar: Option<String>,
    pub timezone: Option<String>,
    /// Raw first-run value retained for compatibility.
    pub first_run: Option<String>,
    /// Raw next-run value retained for compatibility.
    pub next_run: Option<String>,
    pub duration: Option<u32>,
    /// Typed semantics parsed from `icalendar`.
    pub observation: Option<ScheduleObservation>,
    /// Validated first-run timestamp, preferring gvmd's `first_run` field and
    /// falling back to the iCalendar `DTSTART` value.
    pub first_run_at: Option<ScheduleTimestamp>,
    /// Validated next-run timestamp reported by gvmd.
    pub next_run_at: Option<ScheduleTimestamp>,
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
        let icalendar = node.optional_child_text("icalendar");
        let timezone = node.optional_child_text("timezone");
        let observation = icalendar
            .as_deref()
            .map(|icalendar| parse_icalendar_with_timezone(icalendar, timezone.as_deref()))
            .transpose()
            .map_err(|error| ParseError::InvalidValue {
                field: "schedule.icalendar".to_string(),
                value: error.to_string(),
            })?;
        let first_run = node.optional_child_text("first_run");
        let first_run_at = first_run
            .as_deref()
            .map(ScheduleTimestamp::parse)
            .transpose()
            .map_err(|_| ParseError::InvalidValue {
                field: "schedule.first_run".to_string(),
                value: first_run.clone().unwrap_or_default(),
            })?
            .or_else(|| {
                observation
                    .as_ref()
                    .and_then(|value| value.first_run.timestamp().cloned())
            });
        let next_run = node.optional_child_text("next_run");
        let next_run_at = next_run
            .as_deref()
            .map(ScheduleTimestamp::parse)
            .transpose()
            .map_err(|_| ParseError::InvalidValue {
                field: "schedule.next_run".to_string(),
                value: next_run.clone().unwrap_or_default(),
            })?;
        Ok(Self {
            meta: parse_entity_meta(node)?,
            icalendar,
            timezone,
            first_run,
            next_run,
            duration: optional_u32(node, "duration", "duration")?,
            observation,
            first_run_at,
            next_run_at,
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
                    <icalendar>BEGIN:VCALENDAR&#10;VERSION:2.0&#10;BEGIN:VEVENT&#10;DTSTART:20260103T000000Z&#10;RRULE:FREQ=DAILY&#10;END:VEVENT&#10;END:VCALENDAR</icalendar>
                    <timezone>UTC</timezone>
                    <first_run>2026-01-03T00:00:00Z</first_run>
                    <next_run>2026-01-04T00:00:00Z</next_run>
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
        assert_eq!(
            parsed.items[0].first_run.as_deref(),
            Some("2026-01-03T00:00:00Z")
        );
        assert_eq!(
            parsed.items[0].next_run.as_deref(),
            Some("2026-01-04T00:00:00Z")
        );
        assert_eq!(parsed.items[0].duration, Some(3600));
        assert_eq!(
            parsed.items[0]
                .first_run_at
                .as_ref()
                .map(ScheduleTimestamp::as_str),
            Some("2026-01-03T00:00:00Z")
        );
        assert_eq!(
            parsed.items[0]
                .next_run_at
                .as_ref()
                .map(ScheduleTimestamp::as_str),
            Some("2026-01-04T00:00:00Z")
        );
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
        assert_eq!(schedule.first_run, None);
        assert_eq!(schedule.next_run, None);
        assert_eq!(schedule.duration, None);
        assert_eq!(schedule.observation, None);
        assert_eq!(schedule.first_run_at, None);
        assert_eq!(schedule.next_run_at, None);
    }

    #[test]
    fn rejects_invalid_schedule_duration() {
        let response = Response::from(
            r#"<get_schedules_response status="200" status_text="OK">
                <schedule id="s-1">
                    <name>Invalid Duration</name>
                    <duration>forever</duration>
                </schedule>
            </get_schedules_response>"#,
        );

        let error = GetSchedulesResponse::from_response(&response).expect_err("duration must fail");
        assert!(matches!(error, ParseError::InvalidValue { field, value }
                if field == "duration" && value == "forever"));
    }

    #[test]
    fn rejects_invalid_schedule_timestamp() {
        let response = Response::from(
            r#"<get_schedules_response status="200" status_text="OK">
                <schedule id="s-1"><name>Invalid Time</name><next_run>tomorrow</next_run></schedule>
            </get_schedules_response>"#,
        );

        let error = GetSchedulesResponse::from_response(&response).expect_err("time must fail");
        assert!(matches!(error, ParseError::InvalidValue { field, value }
                if field == "schedule.next_run" && value == "tomorrow"));
    }

    #[test]
    fn derives_first_run_from_canonical_zoned_icalendar() {
        let response = Response::from(
            r#"<get_schedules_response status="200" status_text="OK">
                <schedule id="s-1"><name>Zoned</name>
                    <icalendar>BEGIN:VCALENDAR&#13;&#10;BEGIN:VTIMEZONE&#13;&#10;TZID:Europe/Berlin&#13;&#10;BEGIN:STANDARD&#13;&#10;DTSTART:19701025T030000&#13;&#10;END:STANDARD&#13;&#10;END:VTIMEZONE&#13;&#10;BEGIN:VEVENT&#13;&#10;DTSTART;TZID=Europe/Berlin:20300101T080000&#13;&#10;RRULE:FREQ=WEEKLY&#13;&#10;END:VEVENT&#13;&#10;END:VCALENDAR&#13;&#10;</icalendar>
                    <timezone>Europe/Berlin</timezone>
                </schedule>
            </get_schedules_response>"#,
        );

        let parsed = GetSchedulesResponse::from_response(&response).expect("schedule parses");
        let schedule = &parsed.items[0];
        assert_eq!(
            schedule
                .first_run_at
                .as_ref()
                .map(ScheduleTimestamp::as_str),
            Some("2030-01-01T07:00:00Z")
        );
        assert!(matches!(
            schedule.observation.as_ref().map(|value| &value.recurrence),
            Some(crate::schedule::ScheduleRecurrenceObservation::Supported(
                crate::schedule::ScheduleRecurrence::Weekly
            ))
        ));
    }

    #[test]
    fn retains_valid_schedule_with_an_unknown_timezone() {
        let response = Response::from(
            r#"<get_schedules_response status="200" status_text="OK">
                <schedule id="s-1"><name>Custom zone</name>
                    <icalendar>BEGIN:VEVENT&#10;DTSTART:20300101T080000&#10;RRULE:FREQ=DAILY&#10;END:VEVENT</icalendar>
                    <timezone>Custom/Zone</timezone>
                </schedule>
            </get_schedules_response>"#,
        );

        let parsed = GetSchedulesResponse::from_response(&response).expect("schedule parses");
        let schedule = &parsed.items[0];
        assert_eq!(schedule.first_run_at, None);
        assert!(matches!(
            schedule.observation.as_ref().map(|value| &value.first_run),
            Some(crate::schedule::ScheduleStartObservation::Unsupported { .. })
        ));
    }
}
