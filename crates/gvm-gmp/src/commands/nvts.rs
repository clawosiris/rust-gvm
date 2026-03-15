use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::types::EntityId;

#[derive(Debug, Clone, Default)]
pub struct GetNvtsOpts {
    pub filter_string: Option<String>,
    pub filter_id: Option<EntityId>,
    pub details: Option<bool>,
}

pub fn get_nvts(opts: GetNvtsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_nvts");
    add_filter_attrs(&mut cmd, opts.filter_string.as_deref(), opts.filter_id.as_ref());
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

pub fn get_nvt(nvt_oid: &str) -> impl Request {
    XmlCommand::new("get_nvts").attribute("nvt_oid", nvt_oid).attribute("details", "1")
}

pub fn get_nvt_families() -> impl Request {
    XmlCommand::new("get_nvt_families")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId { EntityId::new(value).expect("valid id") }

    #[test]
    fn nvt_commands_build_xml() {
        let rendered = xml(get_nvts(GetNvtsOpts { filter_id: Some(id("f1")), details: Some(true), ..Default::default() }));
        assert!(rendered.contains("filt_id=\"f1\""));
        assert!(rendered.contains("details=\"1\""));
        assert_eq!(xml(get_nvt("1.3.6.1")), "<get_nvts details=\"1\" nvt_oid=\"1.3.6.1\"/>");
        assert_eq!(xml(get_nvt_families()), "<get_nvt_families/>");
    }
}
