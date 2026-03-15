use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::types::EntityId;

#[derive(Debug, Clone, Default)]
pub struct ConfigOpts {
    pub comment: Option<String>,
    pub usage_type: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct GetScanConfigsOpts {
    pub filter_string: Option<String>,
    pub filter_id: Option<EntityId>,
    pub trash: Option<bool>,
    pub details: Option<bool>,
}

pub fn clone_scan_config(config_id: &EntityId) -> impl Request {
    XmlCommand::new("create_config").child_with_text("copy", config_id.as_str())
}

pub fn create_scan_config(name: &str, base_id: Option<&EntityId>, opts: ConfigOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_config");
    cmd.add_element_with_text("name", name);
    if let Some(base_id) = base_id {
        cmd.add_element("copy").set_text(base_id.as_str());
    }
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    add_text_element(&mut cmd, "usage_type", opts.usage_type.as_deref());
    cmd
}

pub fn get_scan_configs(opts: GetScanConfigsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_configs");
    add_filter_attrs(&mut cmd, opts.filter_string.as_deref(), opts.filter_id.as_ref());
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

pub fn get_scan_config(config_id: &EntityId) -> impl Request {
    XmlCommand::new("get_configs").attribute("config_id", config_id.as_str()).attribute("details", "1")
}

pub fn modify_scan_config(config_id: &EntityId, opts: ConfigOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_config").attribute("config_id", config_id.as_str());
    add_text_element(&mut cmd, "name", Some(""));
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    add_text_element(&mut cmd, "usage_type", opts.usage_type.as_deref());
    cmd
}

pub fn delete_scan_config(config_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_config").attribute("config_id", config_id.as_str()).attribute("ultimate", bool_str(ultimate))
}

pub fn sync_config(config_id: &EntityId) -> impl Request {
    XmlCommand::new("sync_config").attribute("config_id", config_id.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId { EntityId::new(value).expect("valid id") }

    #[test]
    fn scan_config_commands_build_xml() {
        let rendered = xml(create_scan_config("cfg", Some(&id("base1")), ConfigOpts { comment: Some("c".into()), usage_type: Some("scan".into()) }));
        assert!(rendered.contains("<copy>base1</copy>"));
        assert_eq!(xml(clone_scan_config(&id("c1"))), "<create_config><copy>c1</copy></create_config>");
        let rendered = xml(get_scan_config(&id("c1")));
        assert!(rendered.contains("<get_configs "));
        assert!(rendered.contains("config_id=\"c1\""));
        assert!(rendered.contains("details=\"1\""));
    }

    #[test]
    fn scan_config_get_modify_delete_sync_build_xml() {
        let rendered = xml(get_scan_configs(GetScanConfigsOpts { filter_string: Some("name=foo".into()), ..Default::default() }));
        assert!(rendered.contains("filter=\"name=foo\""));
        let rendered = xml(modify_scan_config(&id("c1"), ConfigOpts { comment: Some("updated".into()), ..Default::default() }));
        assert_eq!(rendered, "<modify_config config_id=\"c1\"><comment>updated</comment></modify_config>");
        assert_eq!(xml(delete_scan_config(&id("c1"), false)), "<delete_config config_id=\"c1\" ultimate=\"0\"/>");
        assert_eq!(xml(sync_config(&id("c1"))), "<sync_config config_id=\"c1\"/>");
    }
}
