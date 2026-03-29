// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Ticket response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_document, parse_entity_id, parse_entity_meta, parse_named_entity,
    status_from_response, ActionResponse, CountInfo, EntityMeta, NamedEntity, ParseError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ticket {
    pub meta: EntityMeta,
    pub status: Option<String>,
    pub assigned_to: Option<NamedEntity>,
    pub result: Option<NamedEntity>,
    pub task: Option<NamedEntity>,
    pub open_note: Option<String>,
    pub fixed_note: Option<String>,
    pub closed_note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetTicketsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Ticket>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateTicketResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl Ticket {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            status: node.optional_child_text("status"),
            assigned_to: parse_named_entity(node, "assigned_to")?,
            result: parse_named_entity(node, "result")?,
            task: parse_named_entity(node, "task")?,
            open_note: node.optional_child_text("open_note"),
            fixed_note: node.optional_child_text("fixed_note"),
            closed_note: node.optional_child_text("closed_note"),
        })
    }
}

impl GetTicketsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("ticket")
            .map(Ticket::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "ticket_count")?,
        })
    }
}

impl CreateTicketResponse {
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

pub type ModifyTicketResponse = ActionResponse;
pub type DeleteTicketResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_tickets() {
        let response = Response::from(
            r#"<get_tickets_response status="200" status_text="OK">
                <ticket id="tk-1">
                    <owner><name>admin</name></owner>
                    <name>Ticket One</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <status>Open</status>
                    <assigned_to id="u-1"><name>User One</name></assigned_to>
                    <result id="r-1"><name>Result One</name></result>
                    <task id="t-1"><name>Task One</name></task>
                    <open_note>Please fix this</open_note>
                    <fixed_note></fixed_note>
                    <closed_note></closed_note>
                </ticket>
                <ticket id="tk-2">
                    <name>Ticket Two</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                    <status>Fixed</status>
                </ticket>
                <ticket_count>2<filtered>2</filtered><page>1</page></ticket_count>
            </get_tickets_response>"#,
        );

        let parsed = GetTicketsResponse::from_response(&response).expect("tickets parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].status.as_deref(), Some("Open"));
        assert_eq!(
            parsed.items[0]
                .assigned_to
                .as_ref()
                .map(|u| u.name.as_str()),
            Some("User One")
        );
        assert_eq!(
            parsed.items[0].task.as_ref().map(|t| t.name.as_str()),
            Some("Task One")
        );
        assert_eq!(
            parsed.items[0].open_note.as_deref(),
            Some("Please fix this")
        );
        assert_eq!(parsed.items[1].status.as_deref(), Some("Fixed"));
    }

    #[test]
    fn parses_empty_tickets() {
        let response = Response::from(
            r#"<get_tickets_response status="200" status_text="OK"><ticket_count>0<filtered>0</filtered></ticket_count></get_tickets_response>"#,
        );

        let parsed = GetTicketsResponse::from_response(&response).expect("tickets parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_ticket_response() {
        let response = Response::from(
            r#"<create_ticket_response status="201" status_text="OK, resource created" id="tk-1"/>"#,
        );

        let parsed = CreateTicketResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "tk-1");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_tickets_response status="400" status_text="Bad request"/>"#);

        let error = GetTicketsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }

    #[test]
    fn parses_missing_optional_ticket_fields() {
        let response = Response::from(
            r#"<get_tickets_response status="200" status_text="OK">
                <ticket id="tk-1">
                    <name>Only Required</name>
                </ticket>
            </get_tickets_response>"#,
        );

        let parsed = GetTicketsResponse::from_response(&response).expect("tickets parse");
        let ticket = &parsed.items[0];

        assert_eq!(ticket.meta.comment, None);
        assert_eq!(ticket.status, None);
        assert_eq!(ticket.assigned_to, None);
        assert_eq!(ticket.result, None);
        assert_eq!(ticket.task, None);
        assert_eq!(ticket.open_note, None);
    }
}
