use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::TicketStatus;
use crate::types::EntityId;

#[derive(Debug, Clone, Default)]
pub struct TicketOpts {
    pub assigned_to: Option<String>,
    pub comment: Option<String>,
    pub status: Option<TicketStatus>,
    pub open_note: Option<String>,
    pub fixed_note: Option<String>,
    pub closed_note: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct GetTicketsOpts {
    pub filter_string: Option<String>,
    pub filter_id: Option<EntityId>,
    pub trash: Option<bool>,
    pub details: Option<bool>,
}

pub fn clone_ticket(ticket_id: &EntityId) -> impl Request {
    XmlCommand::new("create_ticket").child_with_text("copy", ticket_id.as_str())
}

pub fn create_ticket(result_id: &EntityId, opts: TicketOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_ticket");
    cmd.add_element("result").set_attribute("id", result_id.as_str());
    add_ticket_body(&mut cmd, &opts);
    cmd
}

pub fn get_tickets(opts: GetTicketsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_tickets");
    add_filter_attrs(&mut cmd, opts.filter_string.as_deref(), opts.filter_id.as_ref());
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

pub fn get_ticket(ticket_id: &EntityId) -> impl Request {
    XmlCommand::new("get_tickets").attribute("ticket_id", ticket_id.as_str()).attribute("details", "1")
}

pub fn modify_ticket(ticket_id: &EntityId, opts: TicketOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_ticket").attribute("ticket_id", ticket_id.as_str());
    add_ticket_body(&mut cmd, &opts);
    cmd
}

pub fn delete_ticket(ticket_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_ticket").attribute("ticket_id", ticket_id.as_str()).attribute("ultimate", bool_str(ultimate))
}

fn add_ticket_body(cmd: &mut XmlCommand, opts: &TicketOpts) {
    add_text_element(cmd, "assigned_to", opts.assigned_to.as_deref());
    add_text_element(cmd, "comment", opts.comment.as_deref());
    if let Some(status) = opts.status {
        cmd.add_element_with_text("status", status.as_gmp_str());
    }
    add_text_element(cmd, "open_note", opts.open_note.as_deref());
    add_text_element(cmd, "fixed_note", opts.fixed_note.as_deref());
    add_text_element(cmd, "closed_note", opts.closed_note.as_deref());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId { EntityId::new(value).expect("valid id") }

    #[test]
    fn ticket_commands_build_xml() {
        let rendered = xml(create_ticket(&id("r1"), TicketOpts { comment: Some("c".into()), status: Some(TicketStatus::Open), ..Default::default() }));
        assert!(rendered.contains("<result id=\"r1\"/>"));
        assert!(rendered.contains("<status>open</status>"));
        assert_eq!(xml(clone_ticket(&id("tick1"))), "<create_ticket><copy>tick1</copy></create_ticket>");
        assert_eq!(xml(get_ticket(&id("tick1"))), "<get_tickets details=\"1\" ticket_id=\"tick1\"/>");
    }

    #[test]
    fn ticket_modify_get_delete_build_xml() {
        let rendered = xml(get_tickets(GetTicketsOpts { filter_string: Some("status=open".into()), ..Default::default() }));
        assert!(rendered.contains("filter=\"status=open\""));
        let rendered = xml(modify_ticket(&id("tick1"), TicketOpts { comment: Some("updated".into()), ..Default::default() }));
        assert_eq!(rendered, "<modify_ticket ticket_id=\"tick1\"><comment>updated</comment></modify_ticket>");
        assert_eq!(xml(delete_ticket(&id("tick1"), true)), "<delete_ticket ticket_id=\"tick1\" ultimate=\"1\"/>");
    }
}
