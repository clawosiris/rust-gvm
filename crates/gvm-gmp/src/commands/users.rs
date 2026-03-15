// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! User command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::UserAuthType;
use crate::types::EntityId;

/// Optional fields for user create and modify requests.
#[derive(Debug, Clone, Default)]
pub struct UserOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional password value.
    pub password: Option<String>,
    /// Optional host-access restriction string.
    pub host_access: Option<String>,
    /// Role identifiers assigned to the user.
    pub role_ids: Vec<EntityId>,
    /// Optional user authentication type.
    pub auth_type: Option<UserAuthType>,
}

/// Options for `get_users` requests.
#[derive(Debug, Clone, Default)]
pub struct GetUsersOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Build a clone request for an existing user.
pub fn clone_user(user_id: &EntityId) -> impl Request {
    XmlCommand::new("create_user").child_with_text("copy", user_id.as_str())
}

/// Build a `create_user` request.
pub fn create_user(name: &str, opts: UserOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_user");
    cmd.add_element_with_text("name", name);
    add_user_body(&mut cmd, &opts);
    cmd
}

/// Build a `get_users` request.
pub fn get_users(opts: GetUsersOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_users");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_user` request.
pub fn get_user(user_id: &EntityId) -> impl Request {
    XmlCommand::new("get_users")
        .attribute("user_id", user_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_user` request.
pub fn modify_user(user_id: &EntityId, opts: UserOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_user").attribute("user_id", user_id.as_str());
    add_user_body(&mut cmd, &opts);
    cmd
}

/// Build a `delete_user` request.
pub fn delete_user(user_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_user")
        .attribute("user_id", user_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_user_body(cmd: &mut XmlCommand, opts: &UserOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    add_text_element(cmd, "password", opts.password.as_deref());
    add_text_element(cmd, "hosts", opts.host_access.as_deref());
    if let Some(auth_type) = opts.auth_type {
        cmd.add_element_with_text("authentication", auth_type.as_gmp_str());
    }
    for role_id in &opts.role_ids {
        cmd.add_element("role")
            .set_attribute("id", role_id.as_str());
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
    fn user_commands_build_xml() {
        let rendered = xml(create_user(
            "alice",
            UserOpts {
                password: Some("secret".into()),
                role_ids: vec![id("r1")],
                auth_type: Some(UserAuthType::File),
                ..Default::default()
            },
        ));
        assert!(rendered.contains("<role id=\"r1\"/>"));
        assert!(rendered.contains("<authentication>file</authentication>"));
        assert_eq!(
            xml(clone_user(&id("u1"))),
            "<create_user><copy>u1</copy></create_user>"
        );
        assert_eq!(
            xml(get_user(&id("u1"))),
            "<get_users details=\"1\" user_id=\"u1\"/>"
        );
    }

    #[test]
    fn user_get_modify_delete_build_xml() {
        let rendered = xml(get_users(GetUsersOpts {
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_user(
            &id("u1"),
            UserOpts {
                comment: Some("updated".into()),
                ..Default::default()
            },
        ));
        assert_eq!(
            rendered,
            "<modify_user user_id=\"u1\"><comment>updated</comment></modify_user>"
        );
        let rendered = xml(delete_user(&id("u1"), true));
        assert!(rendered.contains("<delete_user "));
        assert!(rendered.contains("user_id=\"u1\""));
        assert!(rendered.contains("ultimate=\"1\""));
    }
}
