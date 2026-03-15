use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::{EntityType, SeverityLevel};
use crate::types::EntityId;

#[derive(Debug, Clone, Default)]
pub struct TagOpts {
    pub comment: Option<String>,
    pub value: Option<String>,
    pub resource_type: Option<EntityType>,
    pub resource_id: Option<EntityId>,
    pub severity: Option<SeverityLevel>,
    pub active: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct GetTagsOpts {
    pub filter_string: Option<String>,
    pub filter_id: Option<EntityId>,
    pub trash: Option<bool>,
    pub details: Option<bool>,
}

pub fn clone_tag(tag_id: &EntityId) -> impl Request {
    XmlCommand::new("create_tag").child_with_text("copy", tag_id.as_str())
}

pub fn create_tag(name: &str, opts: TagOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_tag");
    cmd.add_element_with_text("name", name);
    add_tag_body(&mut cmd, &opts);
    cmd
}

pub fn get_tags(opts: GetTagsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_tags");
    add_filter_attrs(&mut cmd, opts.filter_string.as_deref(), opts.filter_id.as_ref());
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

pub fn get_tag(tag_id: &EntityId) -> impl Request {
    XmlCommand::new("get_tags").attribute("tag_id", tag_id.as_str()).attribute("details", "1")
}

pub fn modify_tag(tag_id: &EntityId, opts: TagOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_tag").attribute("tag_id", tag_id.as_str());
    add_tag_body(&mut cmd, &opts);
    cmd
}

pub fn delete_tag(tag_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_tag").attribute("tag_id", tag_id.as_str()).attribute("ultimate", bool_str(ultimate))
}

fn add_tag_body(cmd: &mut XmlCommand, opts: &TagOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    add_text_element(cmd, "value", opts.value.as_deref());
    if let Some(resource_type) = opts.resource_type {
        cmd.add_element_with_text("resource_type", resource_type.as_gmp_str());
    }
    if let Some(resource_id) = opts.resource_id.as_ref() {
        cmd.add_element_with_text("resource_id", resource_id.as_str());
    }
    if let Some(severity) = opts.severity {
        cmd.add_element_with_text("severity", severity.as_gmp_str());
    }
    if let Some(active) = opts.active {
        cmd.add_element_with_text("active", bool_str(active));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId { EntityId::new(value).expect("valid id") }

    #[test]
    fn tag_commands_build_xml() {
        let rendered = xml(create_tag("tag", TagOpts { value: Some("blue".into()), resource_type: Some(EntityType::Task), resource_id: Some(id("t1")), severity: Some(SeverityLevel::High), active: Some(true), ..Default::default() }));
        assert!(rendered.contains("<resource_type>task</resource_type>"));
        assert!(rendered.contains("<severity>high</severity>"));
        assert_eq!(xml(clone_tag(&id("tg1"))), "<create_tag><copy>tg1</copy></create_tag>");
        assert_eq!(xml(get_tag(&id("tg1"))), "<get_tags details=\"1\" tag_id=\"tg1\"/>");
    }

    #[test]
    fn tag_get_modify_delete_build_xml() {
        let rendered = xml(get_tags(GetTagsOpts { details: Some(true), ..Default::default() }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_tag(&id("tg1"), TagOpts { comment: Some("updated".into()), ..Default::default() }));
        assert_eq!(rendered, "<modify_tag tag_id=\"tg1\"><comment>updated</comment></modify_tag>");
        assert_eq!(xml(delete_tag(&id("tg1"), false)), "<delete_tag tag_id=\"tg1\" ultimate=\"0\"/>");
    }
}
