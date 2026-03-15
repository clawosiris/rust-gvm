use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::types::EntityId;

#[derive(Debug, Clone, Default)]
pub struct GetResultsOpts {
    pub filter_string: Option<String>,
    pub filter_id: Option<EntityId>,
    pub details: Option<bool>,
}

pub fn get_results(opts: GetResultsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_results");
    add_filter_attrs(&mut cmd, opts.filter_string.as_deref(), opts.filter_id.as_ref());
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

pub fn get_result(result_id: &EntityId) -> impl Request {
    XmlCommand::new("get_results").attribute("result_id", result_id.as_str()).attribute("details", "1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId { EntityId::new(value).expect("valid id") }

    #[test]
    fn result_commands_build_xml() {
        let rendered = xml(get_results(GetResultsOpts { filter_string: Some("severity>5".into()), details: Some(true), ..Default::default() }));
        assert!(rendered.contains("filter=\"severity&gt;5\""));
        assert_eq!(xml(get_result(&id("res1"))), "<get_results details=\"1\" result_id=\"res1\"/>");
    }
}
