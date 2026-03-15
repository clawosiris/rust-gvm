//! Group command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::types::EntityId;

/// Optional fields for group create and modify requests.
#[derive(Debug, Clone, Default)]
pub struct GroupOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// User names associated with the request.
    pub users: Vec<String>,
}

/// Options for `get_groups` requests.
#[derive(Debug, Clone, Default)]
pub struct GetGroupsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Build a clone request for an existing group.
pub fn clone_group(group_id: &EntityId) -> impl Request {
    XmlCommand::new("create_group").child_with_text("copy", group_id.as_str())
}

/// Build a `create_group` request.
pub fn create_group(name: &str, opts: GroupOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_group");
    cmd.add_element_with_text("name", name);
    add_group_body(&mut cmd, &opts);
    cmd
}

/// Build a `get_groups` request.
pub fn get_groups(opts: GetGroupsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_groups");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_group` request.
pub fn get_group(group_id: &EntityId) -> impl Request {
    XmlCommand::new("get_groups")
        .attribute("group_id", group_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_group` request.
pub fn modify_group(group_id: &EntityId, opts: GroupOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_group").attribute("group_id", group_id.as_str());
    add_group_body(&mut cmd, &opts);
    cmd
}

/// Build a `delete_group` request.
pub fn delete_group(group_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_group")
        .attribute("group_id", group_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_group_body(cmd: &mut XmlCommand, opts: &GroupOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    if !opts.users.is_empty() {
        cmd.add_element_with_text("users", &opts.users.join(","));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn group_commands_build_xml() {
        let rendered = xml(create_group(
            "group",
            GroupOpts {
                users: vec!["alice".into()],
                ..Default::default()
            },
        ));
        assert!(rendered.contains("<users>alice</users>"));
        assert_eq!(
            xml(clone_group(&id("g1"))),
            "<create_group><copy>g1</copy></create_group>"
        );
        assert_eq!(
            xml(get_group(&id("g1"))),
            "<get_groups details=\"1\" group_id=\"g1\"/>"
        );
    }

    #[test]
    fn group_get_modify_delete_build_xml() {
        let rendered = xml(get_groups(GetGroupsOpts {
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_group(
            &id("g1"),
            GroupOpts {
                comment: Some("updated".into()),
                ..Default::default()
            },
        ));
        assert_eq!(
            rendered,
            "<modify_group group_id=\"g1\"><comment>updated</comment></modify_group>"
        );
        assert_eq!(
            xml(delete_group(&id("g1"), false)),
            "<delete_group group_id=\"g1\" ultimate=\"0\"/>"
        );
    }
}
