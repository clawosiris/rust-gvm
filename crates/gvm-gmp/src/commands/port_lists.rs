use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::PortRangeType;
use crate::types::EntityId;

#[derive(Debug, Clone, Default)]
pub struct PortListOpts {
    pub comment: Option<String>,
    pub port_range: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct GetPortListsOpts {
    pub filter_string: Option<String>,
    pub filter_id: Option<EntityId>,
    pub trash: Option<bool>,
    pub details: Option<bool>,
}

pub fn clone_port_list(port_list_id: &EntityId) -> impl Request {
    XmlCommand::new("create_port_list").child_with_text("copy", port_list_id.as_str())
}

pub fn create_port_list(name: &str, opts: PortListOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_port_list");
    cmd.add_element_with_text("name", name);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    add_text_element(&mut cmd, "port_range", opts.port_range.as_deref());
    cmd
}

pub fn create_port_range(port_list_id: &EntityId, range_type: PortRangeType, start: u16, end: u16) -> impl Request {
    XmlCommand::new("create_port_range")
        .attribute("port_list_id", port_list_id.as_str())
        .attribute("type", range_type.as_gmp_str())
        .attribute("start", &start.to_string())
        .attribute("end", &end.to_string())
}

pub fn get_port_lists(opts: GetPortListsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_port_lists");
    add_filter_attrs(&mut cmd, opts.filter_string.as_deref(), opts.filter_id.as_ref());
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

pub fn get_port_list(port_list_id: &EntityId) -> impl Request {
    XmlCommand::new("get_port_lists").attribute("port_list_id", port_list_id.as_str()).attribute("details", "1")
}

pub fn modify_port_list(port_list_id: &EntityId, opts: PortListOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_port_list").attribute("port_list_id", port_list_id.as_str());
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    add_text_element(&mut cmd, "port_range", opts.port_range.as_deref());
    cmd
}

pub fn delete_port_list(port_list_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_port_list").attribute("port_list_id", port_list_id.as_str()).attribute("ultimate", bool_str(ultimate))
}

pub fn delete_port_range(port_range_id: &EntityId) -> impl Request {
    XmlCommand::new("delete_port_range").attribute("port_range_id", port_range_id.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId { EntityId::new(value).expect("valid id") }

    #[test]
    fn port_list_commands_build_xml() {
        let rendered = xml(create_port_list("ports", PortListOpts { port_range: Some("T:1-5".into()), ..Default::default() }));
        assert!(rendered.contains("<port_range>T:1-5</port_range>"));
        assert_eq!(xml(clone_port_list(&id("pl1"))), "<create_port_list><copy>pl1</copy></create_port_list>");
        assert_eq!(xml(get_port_list(&id("pl1"))), "<get_port_lists details=\"1\" port_list_id=\"pl1\"/>");
        assert_eq!(xml(create_port_range(&id("pl1"), PortRangeType::Tcp, 1, 5)), "<create_port_range end=\"5\" port_list_id=\"pl1\" start=\"1\" type=\"tcp\"/>");
    }

    #[test]
    fn port_list_get_modify_delete_build_xml() {
        let rendered = xml(get_port_lists(GetPortListsOpts { details: Some(true), ..Default::default() }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_port_list(&id("pl1"), PortListOpts { comment: Some("updated".into()), ..Default::default() }));
        assert_eq!(rendered, "<modify_port_list port_list_id=\"pl1\"><comment>updated</comment></modify_port_list>");
        assert_eq!(xml(delete_port_list(&id("pl1"), false)), "<delete_port_list port_list_id=\"pl1\" ultimate=\"0\"/>");
        assert_eq!(xml(delete_port_range(&id("pr1"))), "<delete_port_range port_range_id=\"pr1\"/>");
    }
}
