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
    /// Optional host-access restrictions.
    pub host_access: Option<UserHostAccess>,
    /// Role identifiers assigned to the user.
    pub role_ids: Vec<EntityId>,
    /// Optional user authentication type.
    pub auth_type: Option<UserAuthType>,
}

/// Optional fields for user modify requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyUserOpts {
    /// Optional replacement name.
    pub new_name: Option<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional password value.
    pub password: Option<String>,
    /// Optional host-access restrictions.
    pub host_access: Option<UserHostAccess>,
    /// Role identifiers assigned to the user.
    pub role_ids: Vec<EntityId>,
    /// Optional user authentication type.
    pub auth_type: Option<UserAuthType>,
}

impl From<UserOpts> for ModifyUserOpts {
    fn from(opts: UserOpts) -> Self {
        Self {
            new_name: None,
            comment: opts.comment,
            password: opts.password,
            host_access: opts.host_access,
            role_ids: opts.role_ids,
            auth_type: opts.auth_type,
        }
    }
}

/// User host-access restrictions.
///
/// `hosts` is the comma-separated GMP host expression string accepted by gvmd.
/// It may contain individual hosts, ranges, or CIDR expressions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UserHostAccess {
    /// If true, allow only the listed hosts; otherwise forbid the listed hosts.
    pub allow: bool,
    /// Comma-separated GMP host expression list.
    pub hosts: String,
}

impl UserHostAccess {
    /// Create user host-access restrictions.
    #[must_use]
    pub fn new(allow: bool, hosts: impl Into<String>) -> Self {
        Self {
            allow,
            hosts: hosts.into(),
        }
    }

    /// Create an allow-list host-access restriction.
    #[must_use]
    pub fn allow(hosts: impl Into<String>) -> Self {
        Self::new(true, hosts)
    }

    /// Create a deny-list host-access restriction.
    #[must_use]
    pub fn deny(hosts: impl Into<String>) -> Self {
        Self::new(false, hosts)
    }
}

impl From<String> for UserHostAccess {
    fn from(hosts: String) -> Self {
        Self::allow(hosts)
    }
}

impl From<&str> for UserHostAccess {
    fn from(hosts: &str) -> Self {
        Self::allow(hosts)
    }
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
#[must_use]
pub fn clone_user(user_id: &EntityId) -> impl Request {
    XmlCommand::new("create_user").child_with_text("copy", user_id.as_str())
}

/// Build a `create_user` request.
#[must_use]
pub fn create_user(name: &str, opts: UserOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_user");
    cmd.add_element_with_text("name", name);
    add_user_body(&mut cmd, &opts);
    cmd
}

/// Build a `get_users` request.
#[must_use]
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
#[must_use]
pub fn get_user(user_id: &EntityId) -> impl Request {
    XmlCommand::new("get_users")
        .attribute("user_id", user_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_user` request.
#[must_use]
pub fn modify_user(user_id: &EntityId, opts: impl Into<ModifyUserOpts>) -> impl Request {
    let opts = opts.into();
    let mut cmd = XmlCommand::new("modify_user").attribute("user_id", user_id.as_str());
    add_text_element(&mut cmd, "new_name", opts.new_name.as_deref());
    add_modify_user_body(&mut cmd, &opts);
    cmd
}

/// Build a `delete_user` request.
#[must_use]
pub fn delete_user(user_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_user")
        .attribute("user_id", user_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_user_body(cmd: &mut XmlCommand, opts: &UserOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    add_text_element(cmd, "password", opts.password.as_deref());
    if let Some(host_access) = &opts.host_access {
        cmd.add_element("hosts")
            .set_attribute("allow", bool_str(host_access.allow))
            .set_text(&host_access.hosts);
    }
    if let Some(auth_type) = opts.auth_type {
        cmd.add_element_with_text("authentication", auth_type.as_gmp_str());
    }
    for role_id in &opts.role_ids {
        cmd.add_element("role")
            .set_attribute("id", role_id.as_str());
    }
}

fn add_modify_user_body(cmd: &mut XmlCommand, opts: &ModifyUserOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    add_text_element(cmd, "password", opts.password.as_deref());
    if let Some(host_access) = &opts.host_access {
        cmd.add_element("hosts")
            .set_attribute("allow", bool_str(host_access.allow))
            .set_text(&host_access.hosts);
    }
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
            ModifyUserOpts {
                new_name: Some("alice-renamed".into()),
                comment: Some("updated".into()),
                ..Default::default()
            },
        ));
        assert_eq!(
            rendered,
            "<modify_user user_id=\"u1\"><new_name>alice-renamed</new_name><comment>updated</comment></modify_user>"
        );
        assert_eq!(
            xml(modify_user(&id("u1"), ModifyUserOpts::default())),
            "<modify_user user_id=\"u1\"/>"
        );
        let rendered = xml(delete_user(&id("u1"), true));
        assert!(rendered.contains("<delete_user "));
        assert!(rendered.contains("user_id=\"u1\""));
        assert!(rendered.contains("ultimate=\"1\""));
    }

    #[test]
    fn modify_user_emits_host_access_allow_mode() {
        let rendered = xml(modify_user(
            &id("u1"),
            UserOpts {
                host_access: Some(UserHostAccess::allow("192.0.2.0/24")),
                ..Default::default()
            },
        ));

        assert_eq!(
            rendered,
            "<modify_user user_id=\"u1\"><hosts allow=\"1\">192.0.2.0/24</hosts></modify_user>"
        );
    }

    #[test]
    fn modify_user_emits_host_access_deny_mode() {
        let rendered = xml(modify_user(
            &id("u1"),
            UserOpts {
                host_access: Some(UserHostAccess::deny("192.0.2.0/24")),
                ..Default::default()
            },
        ));

        assert_eq!(
            rendered,
            "<modify_user user_id=\"u1\"><hosts allow=\"0\">192.0.2.0/24</hosts></modify_user>"
        );
    }

    #[test]
    fn modify_user_emits_explicit_empty_host_access() {
        let rendered = xml(modify_user(
            &id("u1"),
            UserOpts {
                host_access: Some(UserHostAccess::deny("")),
                ..Default::default()
            },
        ));

        assert_eq!(
            rendered,
            "<modify_user user_id=\"u1\"><hosts allow=\"0\"></hosts></modify_user>"
        );
    }
}
