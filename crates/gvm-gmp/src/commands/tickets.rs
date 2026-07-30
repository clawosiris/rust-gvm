// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Ticket command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::TicketStatus;
use crate::types::EntityId;

/// Fields for ticket create requests.
#[derive(Debug, Clone)]
pub struct CreateTicketOpts {
    /// User who will own the ticket.
    pub assigned_to: EntityId,
    /// Required note explaining why the ticket is being opened.
    pub open_note: String,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
}

/// Optional fields for ticket modify requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyTicketOpts {
    /// Optional replacement assignee.
    pub assigned_to: Option<EntityId>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional ticket status.
    pub status: Option<TicketStatus>,
    /// Optional note for the open state.
    pub open_note: Option<String>,
    /// Optional note for the fixed state.
    pub fixed_note: Option<String>,
    /// Optional note for the closed state.
    pub closed_note: Option<String>,
}

/// Options for `get_tickets` requests.
#[derive(Debug, Clone, Default)]
pub struct GetTicketsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Build a clone request for an existing ticket.
#[must_use]
pub fn clone_ticket(ticket_id: &EntityId) -> impl Request {
    XmlCommand::new("create_ticket").child_with_text("copy", ticket_id.as_str())
}

/// Build a `create_ticket` request.
#[must_use]
pub fn create_ticket(result_id: &EntityId, opts: CreateTicketOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_ticket");
    cmd.add_element("result")
        .set_attribute("id", result_id.as_str());
    add_assignee(&mut cmd, &opts.assigned_to);
    cmd.add_element_with_text("open_note", &opts.open_note);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    cmd
}

/// Build a `get_tickets` request.
#[must_use]
pub fn get_tickets(opts: GetTicketsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_tickets");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_ticket` request.
#[must_use]
pub fn get_ticket(ticket_id: &EntityId) -> impl Request {
    XmlCommand::new("get_tickets")
        .attribute("ticket_id", ticket_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_ticket` request.
#[must_use]
pub fn modify_ticket(ticket_id: &EntityId, opts: ModifyTicketOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_ticket").attribute("ticket_id", ticket_id.as_str());
    add_modify_ticket_body(&mut cmd, &opts);
    cmd
}

/// Build a `delete_ticket` request.
#[must_use]
pub fn delete_ticket(ticket_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_ticket")
        .attribute("ticket_id", ticket_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_modify_ticket_body(cmd: &mut XmlCommand, opts: &ModifyTicketOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    if let Some(status) = opts.status {
        cmd.add_element_with_text("status", status.as_ticket_status());
    }
    add_text_element(cmd, "open_note", opts.open_note.as_deref());
    add_text_element(cmd, "fixed_note", opts.fixed_note.as_deref());
    add_text_element(cmd, "closed_note", opts.closed_note.as_deref());
    if let Some(assigned_to) = opts.assigned_to.as_ref() {
        add_assignee(cmd, assigned_to);
    }
}

fn add_assignee(cmd: &mut XmlCommand, assigned_to: &EntityId) {
    cmd.add_element("assigned_to")
        .add_child("user")
        .set_attribute("id", assigned_to.as_str());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn ticket_commands_build_xml() {
        let rendered = xml(create_ticket(
            &id("r1"),
            CreateTicketOpts {
                assigned_to: id("u1"),
                open_note: "Please fix <today>".into(),
                comment: Some("c".into()),
            },
        ));
        assert_eq!(
            rendered,
            "<create_ticket><result id=\"r1\"/><assigned_to><user id=\"u1\"/></assigned_to><open_note>Please fix &lt;today&gt;</open_note><comment>c</comment></create_ticket>"
        );
        assert_eq!(
            xml(clone_ticket(&id("tick1"))),
            "<create_ticket><copy>tick1</copy></create_ticket>"
        );
        assert_eq!(
            xml(get_ticket(&id("tick1"))),
            "<get_tickets details=\"1\" ticket_id=\"tick1\"/>"
        );
    }

    #[test]
    fn ticket_modify_get_delete_build_xml() {
        let rendered = xml(get_tickets(GetTicketsOpts {
            filter_string: Some("status=open".into()),
            ..Default::default()
        }));
        assert!(rendered.contains("filter=\"status=open\""));
        let rendered = xml(modify_ticket(
            &id("tick1"),
            ModifyTicketOpts {
                assigned_to: Some(id("u2")),
                comment: Some("updated".into()),
                ..Default::default()
            },
        ));
        assert_eq!(
            rendered,
            "<modify_ticket ticket_id=\"tick1\"><comment>updated</comment><assigned_to><user id=\"u2\"/></assigned_to></modify_ticket>"
        );
        assert_eq!(
            xml(modify_ticket(&id("tick1"), ModifyTicketOpts::default())),
            "<modify_ticket ticket_id=\"tick1\"/>"
        );
        assert_eq!(
            xml(delete_ticket(&id("tick1"), true)),
            "<delete_ticket ticket_id=\"tick1\" ultimate=\"1\"/>"
        );
    }
}
