// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Note response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_bool, parse_csv_list, parse_document, parse_entity_id,
    parse_entity_meta_optional_name, parse_entity_ref, status_from_response, ActionResponse,
    CountInfo, EntityMeta, NamedEntity, ParseError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Note {
    pub meta: EntityMeta,
    pub text: Option<String>,
    pub nvt_oid: Option<String>,
    pub hosts: Vec<String>,
    pub port: Option<String>,
    pub severity: Option<String>,
    pub task: Option<NamedEntity>,
    pub result: Option<NamedEntity>,
    pub active: bool,
    pub end_time: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetNotesResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Note>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateNoteResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl Note {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta_optional_name(node)?,
            text: node.optional_child_text("text"),
            nvt_oid: node
                .child("nvt")
                .and_then(|n| n.attr("oid"))
                .map(String::from),
            hosts: node
                .optional_child_text("hosts")
                .map(|value| parse_csv_list(&value))
                .unwrap_or_default(),
            port: node.optional_child_text("port"),
            severity: node.optional_child_text("severity"),
            task: parse_entity_ref(node, "task")?,
            result: parse_entity_ref(node, "result")?,
            active: node
                .optional_child_text("active")
                .map(|value| parse_bool(&value, "active"))
                .transpose()?
                .unwrap_or(false),
            end_time: node.optional_child_text("end_time"),
        })
    }
}

impl GetNotesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("note")
            .map(Note::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "note_count")?,
        })
    }
}

impl CreateNoteResponse {
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

pub type ModifyNoteResponse = ActionResponse;
pub type DeleteNoteResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_notes() {
        let response = Response::from(
            r#"<get_notes_response status="200" status_text="OK">
                <note id="n-1">
                    <owner><name>admin</name></owner>
                    <name>Note One</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <text>This is a note</text>
                    <nvt oid="1.3.6.1.4.1.25623.1.0.12345"><name>Some NVT</name></nvt>
                    <hosts>192.168.1.1, 192.168.1.2, </hosts>
                    <port>80/tcp</port>
                    <severity>5.0</severity>
                    <task id="t-1"><name>Task One</name></task>
                    <result id="r-1"><name>Result One</name></result>
                    <active>1</active>
                    <end_time>2027-01-01T00:00:00Z</end_time>
                </note>
                <note id="n-2">
                    <name>Note Two</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                    <active>0</active>
                </note>
                <note_count>2<filtered>2</filtered><page>1</page></note_count>
            </get_notes_response>"#,
        );

        let parsed = GetNotesResponse::from_response(&response).expect("notes parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].text.as_deref(), Some("This is a note"));
        assert_eq!(
            parsed.items[0].nvt_oid.as_deref(),
            Some("1.3.6.1.4.1.25623.1.0.12345")
        );
        assert_eq!(
            parsed.items[0].hosts,
            vec!["192.168.1.1".to_string(), "192.168.1.2".to_string()]
        );
        assert_eq!(parsed.items[0].port.as_deref(), Some("80/tcp"));
        assert_eq!(
            parsed.items[0].task.as_ref().map(|t| t.name.as_str()),
            Some("Task One")
        );
        assert!(parsed.items[0].active);
        assert!(!parsed.items[1].active);
    }

    #[test]
    fn parses_empty_notes() {
        let response = Response::from(
            r#"<get_notes_response status="200" status_text="OK"><note_count>0<filtered>0</filtered></note_count></get_notes_response>"#,
        );

        let parsed = GetNotesResponse::from_response(&response).expect("notes parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_note_response() {
        let response = Response::from(
            r#"<create_note_response status="201" status_text="OK, resource created" id="n-1"/>"#,
        );

        let parsed = CreateNoteResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "n-1");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_notes_response status="400" status_text="Bad request"/>"#);

        let error = GetNotesResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }

    #[test]
    fn parses_missing_optional_note_fields() {
        let response = Response::from(
            r#"<get_notes_response status="200" status_text="OK">
                <note id="n-1">
                    <name>Only Required</name>
                </note>
            </get_notes_response>"#,
        );

        let parsed = GetNotesResponse::from_response(&response).expect("notes parse");
        let note = &parsed.items[0];

        assert_eq!(note.meta.comment, None);
        assert_eq!(note.text, None);
        assert_eq!(note.nvt_oid, None);
        assert!(note.hosts.is_empty());
        assert_eq!(note.task, None);
        assert!(!note.active);
    }

    #[test]
    fn parses_gvmd_note_without_top_level_name() {
        let response = Response::from(
            r#"<get_notes_response status="200" status_text="OK">
                <note id="139bd467-d6dc-46a6-9297-0f2bbaec342a">
                    <permissions><permission><name>Everything</name></permission></permissions>
                    <owner><name>admin</name></owner>
                    <nvt oid="1.3.6.1.4.1.25623.1.0.12288"><name>Global variable settings</name><type>nvt</type></nvt>
                    <creation_time>2026-06-10T12:41:51Z</creation_time>
                    <modification_time>2026-06-10T12:41:51Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <active>1</active>
                    <end_time>2026-06-11T12:41:51Z</end_time>
                    <text>raw gmp parser repro</text>
                    <hosts></hosts>
                    <port></port>
                    <severity></severity>
                    <task id=""><name></name><trash>0</trash></task>
                    <orphan>0</orphan>
                    <result id=""/>
                </note>
            </get_notes_response>"#,
        );

        let parsed = GetNotesResponse::from_response(&response).expect("note parses");
        let note = &parsed.items[0];

        assert_eq!(
            note.meta.id.as_str(),
            "139bd467-d6dc-46a6-9297-0f2bbaec342a"
        );
        assert_eq!(note.meta.name, "");
        assert_eq!(
            note.meta.owner.as_ref().map(|owner| owner.name.as_str()),
            Some("admin")
        );
        assert_eq!(
            note.meta.creation_time.as_deref(),
            Some("2026-06-10T12:41:51Z")
        );
        assert_eq!(
            note.meta.modification_time.as_deref(),
            Some("2026-06-10T12:41:51Z")
        );
        assert!(note.meta.writable);
        assert!(!note.meta.in_use);
        assert!(note.active);
        assert_eq!(note.end_time.as_deref(), Some("2026-06-11T12:41:51Z"));
        assert_eq!(note.text.as_deref(), Some("raw gmp parser repro"));
        assert_eq!(note.nvt_oid.as_deref(), Some("1.3.6.1.4.1.25623.1.0.12288"));
        assert!(note.hosts.is_empty());
        assert_eq!(note.port, None);
        assert_eq!(note.severity, None);
        assert_eq!(note.task, None);
        assert_eq!(note.result, None);
    }

    #[test]
    fn parses_note_with_id_only_task_and_result_refs() {
        let response = Response::from(
            r#"<get_notes_response status="200" status_text="OK">
                <note id="n-1">
                    <name>Note One</name>
                    <task id="t-1"/>
                    <result id="r-1"/>
                </note>
            </get_notes_response>"#,
        );

        let parsed = GetNotesResponse::from_response(&response).expect("note parses");
        let note = &parsed.items[0];

        let task = note.task.as_ref().expect("task ref");
        assert_eq!(task.id.as_str(), "t-1");
        assert_eq!(task.name, "");

        let result = note.result.as_ref().expect("result ref");
        assert_eq!(result.id.as_str(), "r-1");
        assert_eq!(result.name, "");
    }
}
