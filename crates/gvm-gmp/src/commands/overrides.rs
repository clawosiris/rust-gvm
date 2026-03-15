use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::types::EntityId;

#[derive(Debug, Clone, Default)]
pub struct OverrideOpts {
    pub text: Option<String>,
    pub hosts: Vec<String>,
    pub port: Option<String>,
    pub severity: Option<String>,
    pub new_severity: Option<String>,
    pub task_id: Option<EntityId>,
    pub result_id: Option<EntityId>,
    pub active: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct GetOverridesOpts {
    pub filter_string: Option<String>,
    pub filter_id: Option<EntityId>,
    pub trash: Option<bool>,
    pub details: Option<bool>,
}

pub fn clone_override(override_id: &EntityId) -> impl Request {
    XmlCommand::new("create_override").child_with_text("copy", override_id.as_str())
}

pub fn create_override(nvt_oid: &str, opts: OverrideOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_override");
    cmd.add_element("nvt").set_attribute("oid", nvt_oid);
    add_override_body(&mut cmd, &opts);
    cmd
}

pub fn get_overrides(opts: GetOverridesOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_overrides");
    add_filter_attrs(&mut cmd, opts.filter_string.as_deref(), opts.filter_id.as_ref());
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

pub fn get_override(override_id: &EntityId) -> impl Request {
    XmlCommand::new("get_overrides").attribute("override_id", override_id.as_str()).attribute("details", "1")
}

pub fn modify_override(override_id: &EntityId, opts: OverrideOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_override").attribute("override_id", override_id.as_str());
    add_override_body(&mut cmd, &opts);
    cmd
}

pub fn delete_override(override_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_override").attribute("override_id", override_id.as_str()).attribute("ultimate", bool_str(ultimate))
}

fn add_override_body(cmd: &mut XmlCommand, opts: &OverrideOpts) {
    add_text_element(cmd, "text", opts.text.as_deref());
    if !opts.hosts.is_empty() {
        cmd.add_element_with_text("hosts", &opts.hosts.join(","));
    }
    add_text_element(cmd, "port", opts.port.as_deref());
    add_text_element(cmd, "severity", opts.severity.as_deref());
    add_text_element(cmd, "new_severity", opts.new_severity.as_deref());
    if let Some(task_id) = opts.task_id.as_ref() {
        cmd.add_element("task").set_attribute("id", task_id.as_str());
    }
    if let Some(result_id) = opts.result_id.as_ref() {
        cmd.add_element("result").set_attribute("id", result_id.as_str());
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
    fn override_commands_build_xml() {
        let rendered = xml(create_override("oid", OverrideOpts { text: Some("body".into()), new_severity: Some("7.5".into()), ..Default::default() }));
        assert!(rendered.contains("<nvt oid=\"oid\"/>"));
        assert!(rendered.contains("<new_severity>7.5</new_severity>"));
        assert_eq!(xml(clone_override(&id("o1"))), "<create_override><copy>o1</copy></create_override>");
        assert_eq!(xml(get_override(&id("o1"))), "<get_overrides details=\"1\" override_id=\"o1\"/>");
    }

    #[test]
    fn override_modify_get_delete_build_xml() {
        let rendered = xml(get_overrides(GetOverridesOpts { filter_string: Some("name=foo".into()), details: Some(true), ..Default::default() }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_override(&id("o1"), OverrideOpts { text: Some("updated".into()), ..Default::default() }));
        assert_eq!(rendered, "<modify_override override_id=\"o1\"><text>updated</text></modify_override>");
        assert_eq!(xml(delete_override(&id("o1"), false)), "<delete_override override_id=\"o1\" ultimate=\"0\"/>");
    }
}
