use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::{FilterType, SortOrder};
use crate::types::EntityId;

#[derive(Debug, Clone, Default)]
pub struct FilterOpts {
    pub comment: Option<String>,
    pub term: Option<String>,
    pub filter_type: Option<FilterType>,
    pub sort_order: Option<SortOrder>,
}

#[derive(Debug, Clone, Default)]
pub struct GetFiltersOpts {
    pub filter_string: Option<String>,
    pub filter_id: Option<EntityId>,
    pub trash: Option<bool>,
    pub details: Option<bool>,
}

pub fn clone_filter(filter_id: &EntityId) -> impl Request {
    XmlCommand::new("create_filter").child_with_text("copy", filter_id.as_str())
}

pub fn create_filter(name: &str, opts: FilterOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_filter");
    cmd.add_element_with_text("name", name);
    add_filter_body(&mut cmd, &opts);
    cmd
}

pub fn get_filters(opts: GetFiltersOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_filters");
    add_filter_attrs(&mut cmd, opts.filter_string.as_deref(), opts.filter_id.as_ref());
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

pub fn get_filter(filter_id: &EntityId) -> impl Request {
    XmlCommand::new("get_filters").attribute("filter_id", filter_id.as_str()).attribute("details", "1")
}

pub fn modify_filter(filter_id: &EntityId, opts: FilterOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_filter").attribute("filter_id", filter_id.as_str());
    add_filter_body(&mut cmd, &opts);
    cmd
}

pub fn delete_filter(filter_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_filter").attribute("filter_id", filter_id.as_str()).attribute("ultimate", bool_str(ultimate))
}

fn add_filter_body(cmd: &mut XmlCommand, opts: &FilterOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    add_text_element(cmd, "term", opts.term.as_deref());
    if let Some(filter_type) = opts.filter_type {
        cmd.add_element_with_text("type", filter_type.as_gmp_str());
    }
    if let Some(sort_order) = opts.sort_order {
        cmd.add_element_with_text("sort_order", sort_order.as_gmp_str());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId { EntityId::new(value).expect("valid id") }

    #[test]
    fn filter_commands_build_xml() {
        let rendered = xml(create_filter("f", FilterOpts { term: Some("rows=10".into()), filter_type: Some(FilterType::Task), sort_order: Some(SortOrder::Ascending), ..Default::default() }));
        assert!(rendered.contains("<term>rows=10</term>"));
        assert_eq!(xml(clone_filter(&id("f1"))), "<create_filter><copy>f1</copy></create_filter>");
        assert_eq!(xml(get_filter(&id("f1"))), "<get_filters details=\"1\" filter_id=\"f1\"/>");
    }

    #[test]
    fn filter_get_modify_delete_build_xml() {
        let rendered = xml(get_filters(GetFiltersOpts { details: Some(true), ..Default::default() }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_filter(&id("f1"), FilterOpts { comment: Some("updated".into()), ..Default::default() }));
        assert_eq!(rendered, "<modify_filter filter_id=\"f1\"><comment>updated</comment></modify_filter>");
        assert_eq!(xml(delete_filter(&id("f1"), false)), "<delete_filter filter_id=\"f1\" ultimate=\"0\"/>");
    }
}
