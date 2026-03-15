// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Role command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::types::EntityId;

/// Optional fields for role create and modify requests.
#[derive(Debug, Clone, Default)]
pub struct RoleOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// User names associated with the request.
    pub users: Vec<String>,
}

/// Options for `get_roles` requests.
#[derive(Debug, Clone, Default)]
pub struct GetRolesOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Build a clone request for an existing role.
#[must_use]
pub fn clone_role(role_id: &EntityId) -> impl Request {
    XmlCommand::new("create_role").child_with_text("copy", role_id.as_str())
}

/// Build a `create_role` request.
#[must_use]
pub fn create_role(name: &str, opts: RoleOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_role");
    cmd.add_element_with_text("name", name);
    add_role_body(&mut cmd, &opts);
    cmd
}

/// Build a `get_roles` request.
#[must_use]
pub fn get_roles(opts: GetRolesOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_roles");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_role` request.
#[must_use]
pub fn get_role(role_id: &EntityId) -> impl Request {
    XmlCommand::new("get_roles")
        .attribute("role_id", role_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_role` request.
#[must_use]
pub fn modify_role(role_id: &EntityId, opts: RoleOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_role").attribute("role_id", role_id.as_str());
    add_role_body(&mut cmd, &opts);
    cmd
}

/// Build a `delete_role` request.
#[must_use]
pub fn delete_role(role_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_role")
        .attribute("role_id", role_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_role_body(cmd: &mut XmlCommand, opts: &RoleOpts) {
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
    fn role_commands_build_xml() {
        let rendered = xml(create_role(
            "role",
            RoleOpts {
                users: vec!["alice".into()],
                ..Default::default()
            },
        ));
        assert!(rendered.contains("<users>alice</users>"));
        assert_eq!(
            xml(clone_role(&id("r1"))),
            "<create_role><copy>r1</copy></create_role>"
        );
        assert_eq!(
            xml(get_role(&id("r1"))),
            "<get_roles details=\"1\" role_id=\"r1\"/>"
        );
    }

    #[test]
    fn role_get_modify_delete_build_xml() {
        let rendered = xml(get_roles(GetRolesOpts {
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_role(
            &id("r1"),
            RoleOpts {
                comment: Some("updated".into()),
                ..Default::default()
            },
        ));
        assert_eq!(
            rendered,
            "<modify_role role_id=\"r1\"><comment>updated</comment></modify_role>"
        );
        assert_eq!(
            xml(delete_role(&id("r1"), false)),
            "<delete_role role_id=\"r1\" ultimate=\"0\"/>"
        );
    }
}
