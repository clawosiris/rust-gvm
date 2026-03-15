use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::types::EntityId;

#[derive(Debug, Clone, Default)]
pub struct HostOpts {
    pub comment: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct GetHostsOpts {
    pub filter_string: Option<String>,
    pub filter_id: Option<EntityId>,
    pub trash: Option<bool>,
    pub details: Option<bool>,
}

pub fn create_host(opts: HostOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_asset");
    cmd.add_element_with_text("asset_type", "host");
    add_host_body(&mut cmd, &opts);
    cmd
}

pub fn get_hosts(opts: GetHostsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_assets").attribute("asset_type", "host");
    add_filter_attrs(&mut cmd, opts.filter_string.as_deref(), opts.filter_id.as_ref());
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

pub fn get_host(host_id: &EntityId) -> impl Request {
    XmlCommand::new("get_assets").attribute("asset_id", host_id.as_str()).attribute("asset_type", "host").attribute("details", "1")
}

pub fn modify_host(host_id: &EntityId, opts: HostOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_asset").attribute("asset_id", host_id.as_str());
    add_host_body(&mut cmd, &opts);
    cmd
}

pub fn delete_host(host_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_asset").attribute("asset_id", host_id.as_str()).attribute("ultimate", bool_str(ultimate))
}

fn add_host_body(cmd: &mut XmlCommand, opts: &HostOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    add_text_element(cmd, "value", opts.value.as_deref());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId { EntityId::new(value).expect("valid id") }

    #[test]
    fn host_commands_build_xml() {
        let rendered = xml(create_host(HostOpts { value: Some("1.1.1.1".into()), ..Default::default() }));
        assert!(rendered.contains("<asset_type>host</asset_type>"));
        assert!(rendered.contains("<value>1.1.1.1</value>"));
        assert_eq!(xml(get_host(&id("h1"))), "<get_assets asset_id=\"h1\" asset_type=\"host\" details=\"1\"/>");
    }

    #[test]
    fn host_get_modify_delete_build_xml() {
        let rendered = xml(get_hosts(GetHostsOpts { details: Some(true), ..Default::default() }));
        assert!(rendered.contains("asset_type=\"host\""));
        let rendered = xml(modify_host(&id("h1"), HostOpts { comment: Some("updated".into()), ..Default::default() }));
        assert_eq!(rendered, "<modify_asset asset_id=\"h1\"><comment>updated</comment></modify_asset>");
        assert_eq!(xml(delete_host(&id("h1"), false)), "<delete_asset asset_id=\"h1\" ultimate=\"0\"/>");
    }
}
