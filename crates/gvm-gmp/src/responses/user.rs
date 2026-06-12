// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! User response models.

use gvm_protocol::Response;

use crate::commands::users::UserHostAccess;
use crate::responses::common::{
    count_info, parse_document, parse_entity_id, parse_entity_meta, status_from_response,
    ActionResponse, CountInfo, EntityMeta, NamedEntity, ParseError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct User {
    pub meta: EntityMeta,
    pub roles: Vec<NamedEntity>,
    pub groups: Vec<NamedEntity>,
    pub hosts_allow: Option<String>,
    pub hosts: Option<String>,
    pub authentication_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetUsersResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<User>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateUserResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl User {
    /// Return host-access restrictions in the form accepted by `modify_user`.
    ///
    /// gvmd represents the host list as a comma-separated string. A missing
    /// `allow` value defaults to allow mode, matching gvmd's command parser.
    #[must_use]
    pub fn host_access(&self) -> Option<UserHostAccess> {
        let hosts = self.hosts.clone()?;
        let allow = self
            .hosts_allow
            .as_deref()
            .map(|value| !matches!(value, "0" | "false"))
            .unwrap_or(true);
        Some(UserHostAccess::new(allow, hosts))
    }

    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        let roles = node
            .children_named("role")
            .map(|r| {
                let id = parse_entity_id(
                    r.attr("id")
                        .ok_or_else(|| ParseError::MissingElement("role.id".to_string()))?,
                    "role.id",
                )?;
                let name = r.required_child_text("name")?;
                Ok(NamedEntity { id, name })
            })
            .collect::<Result<Vec<_>, ParseError>>()?;

        let groups = node
            .child("groups")
            .map(|groups_node| {
                groups_node
                    .children_named("group")
                    .map(|g| {
                        let id = parse_entity_id(
                            g.attr("id").ok_or_else(|| {
                                ParseError::MissingElement("group.id".to_string())
                            })?,
                            "group.id",
                        )?;
                        let name = g.required_child_text("name")?;
                        Ok(NamedEntity { id, name })
                    })
                    .collect::<Result<Vec<_>, ParseError>>()
            })
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            meta: parse_entity_meta(node)?,
            roles,
            groups,
            hosts_allow: node.optional_child_text("hosts_allow").or_else(|| {
                node.child("hosts")
                    .and_then(|hosts| hosts.attr("allow"))
                    .map(ToString::to_string)
            }),
            hosts: node.child_text("hosts"),
            authentication_type: node
                .child("sources")
                .and_then(|sources| sources.optional_child_text("source"))
                .or_else(|| node.optional_child_text("authentication")),
        })
    }
}

impl GetUsersResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("user")
            .map(User::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "user_count")?,
        })
    }
}

impl CreateUserResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let id = parse_entity_id(
            root.attr("id")
                .ok_or_else(|| ParseError::MissingElement("id".to_string()))?,
            "id",
        )?;
        Ok(Self {
            status,
            status_text,
            id,
        })
    }
}

pub type ModifyUserResponse = ActionResponse;
pub type DeleteUserResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::{Request, Response};

    use crate::commands::users::{modify_user, UserOpts};

    use super::*;

    #[test]
    fn parses_multiple_users() {
        let response = Response::from(
            r#"<get_users_response status="200" status_text="OK">
                <user id="u-1">
                    <owner><name>admin</name></owner>
                    <name>User One</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <role id="r-1"><name>Admin</name></role>
                    <role id="r-2"><name>Observer</name></role>
                    <groups>
                        <group id="g-1"><name>Group One</name></group>
                    </groups>
                    <hosts_allow>0</hosts_allow>
                    <hosts>192.168.1.0/24</hosts>
                    <sources><source>file</source></sources>
                </user>
                <user id="u-2">
                    <name>User Two</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                    <sources><source>future_auth_backend</source></sources>
                </user>
                <user_count>2<filtered>2</filtered><page>1</page></user_count>
            </get_users_response>"#,
        );

        let parsed = GetUsersResponse::from_response(&response).expect("users parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].roles.len(), 2);
        assert_eq!(parsed.items[0].roles[0].name, "Admin");
        assert_eq!(parsed.items[0].roles[1].name, "Observer");
        assert_eq!(parsed.items[0].groups.len(), 1);
        assert_eq!(parsed.items[0].groups[0].name, "Group One");
        assert_eq!(parsed.items[0].hosts_allow.as_deref(), Some("0"));
        assert_eq!(parsed.items[0].hosts.as_deref(), Some("192.168.1.0/24"));
        assert_eq!(
            parsed.items[0].host_access(),
            Some(UserHostAccess::deny("192.168.1.0/24"))
        );
        assert_eq!(parsed.items[0].authentication_type.as_deref(), Some("file"));
        assert_eq!(
            parsed.items[1].authentication_type.as_deref(),
            Some("future_auth_backend")
        );
        assert!(parsed.items[1].meta.in_use);
    }

    #[test]
    fn parses_empty_users() {
        let response = Response::from(
            r#"<get_users_response status="200" status_text="OK"><user_count>0<filtered>0</filtered></user_count></get_users_response>"#,
        );

        let parsed = GetUsersResponse::from_response(&response).expect("users parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_user_response() {
        let response = Response::from(
            r#"<create_user_response status="201" status_text="OK, resource created" id="u-1"/>"#,
        );

        let parsed = CreateUserResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "u-1");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_users_response status="400" status_text="Bad request"/>"#);

        let error = GetUsersResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }

    #[test]
    fn parses_missing_optional_user_fields() {
        let response = Response::from(
            r#"<get_users_response status="200" status_text="OK">
                <user id="u-1">
                    <name>Only Required</name>
                </user>
            </get_users_response>"#,
        );

        let parsed = GetUsersResponse::from_response(&response).expect("users parse");
        let user = &parsed.items[0];

        assert_eq!(user.meta.comment, None);
        assert!(user.roles.is_empty());
        assert!(user.groups.is_empty());
        assert_eq!(user.hosts_allow, None);
        assert_eq!(user.hosts, None);
        assert_eq!(user.host_access(), None);
        assert_eq!(user.authentication_type, None);
    }

    #[test]
    fn parses_hosts_allow_attribute_shape() {
        let response = Response::from(
            r#"<get_users_response status="200" status_text="OK">
                <user id="u-1">
                    <name>User One</name>
                    <hosts allow="1">192.168.1.0/24, 192.168.2.0/24</hosts>
                </user>
            </get_users_response>"#,
        );

        let parsed = GetUsersResponse::from_response(&response).expect("users parse");
        let user = &parsed.items[0];

        assert_eq!(user.hosts_allow.as_deref(), Some("1"));
        assert_eq!(
            user.hosts.as_deref(),
            Some("192.168.1.0/24, 192.168.2.0/24")
        );
        assert_eq!(
            user.host_access(),
            Some(UserHostAccess::allow("192.168.1.0/24, 192.168.2.0/24"))
        );
    }

    #[test]
    fn round_trips_hosts_allow_attribute_to_modify_user() {
        let response = Response::from(
            r#"<get_users_response status="200" status_text="OK">
                <user id="u-1">
                    <name>User One</name>
                    <hosts allow="0">192.168.1.0/24</hosts>
                </user>
            </get_users_response>"#,
        );

        let parsed = GetUsersResponse::from_response(&response).expect("users parse");
        let user = &parsed.items[0];
        let rendered = String::from_utf8(
            modify_user(
                &user.meta.id,
                UserOpts {
                    comment: Some("updated".into()),
                    host_access: user.host_access(),
                    ..Default::default()
                },
            )
            .to_bytes(),
        )
        .expect("request XML should be UTF-8");

        assert_eq!(
            rendered,
            "<modify_user user_id=\"u-1\"><comment>updated</comment><hosts allow=\"0\">192.168.1.0/24</hosts></modify_user>"
        );
    }

    #[test]
    fn preserves_explicit_empty_hosts_for_round_trip() {
        let response = Response::from(
            r#"<get_users_response status="200" status_text="OK">
                <user id="u-1">
                    <name>User One</name>
                    <hosts allow="0"></hosts>
                </user>
            </get_users_response>"#,
        );

        let parsed = GetUsersResponse::from_response(&response).expect("users parse");
        let user = &parsed.items[0];

        assert_eq!(user.hosts_allow.as_deref(), Some("0"));
        assert_eq!(user.hosts.as_deref(), Some(""));
        assert_eq!(user.host_access(), Some(UserHostAccess::deny("")));
    }

    #[test]
    fn parses_false_hosts_allow_sibling_as_deny_mode() {
        let response = Response::from(
            r#"<get_users_response status="200" status_text="OK">
                <user id="u-1">
                    <name>User One</name>
                    <hosts_allow>false</hosts_allow>
                    <hosts>192.168.1.0/24</hosts>
                </user>
            </get_users_response>"#,
        );

        let parsed = GetUsersResponse::from_response(&response).expect("users parse");
        let user = &parsed.items[0];

        assert_eq!(
            user.host_access(),
            Some(UserHostAccess::deny("192.168.1.0/24"))
        );
    }

    #[test]
    fn parses_false_hosts_allow_attribute_as_deny_mode() {
        let response = Response::from(
            r#"<get_users_response status="200" status_text="OK">
                <user id="u-1">
                    <name>User One</name>
                    <hosts allow="false">192.168.1.0/24</hosts>
                </user>
            </get_users_response>"#,
        );

        let parsed = GetUsersResponse::from_response(&response).expect("users parse");
        let user = &parsed.items[0];

        assert_eq!(
            user.host_access(),
            Some(UserHostAccess::deny("192.168.1.0/24"))
        );
    }

    #[test]
    fn parses_known_user_authentication_types() {
        let response = Response::from(
            r#"<get_users_response status="200" status_text="OK">
                <user id="u-1"><name>Alice</name><sources><source>file</source></sources></user>
                <user id="u-2"><name>Bob</name><sources><source>ldap_connect</source></sources></user>
                <user id="u-3"><name>Carol</name><sources><source>radius_connect</source></sources></user>
            </get_users_response>"#,
        );

        let parsed = GetUsersResponse::from_response(&response).expect("users parse");

        assert_eq!(parsed.items[0].authentication_type.as_deref(), Some("file"));
        assert_eq!(
            parsed.items[1].authentication_type.as_deref(),
            Some("ldap_connect")
        );
        assert_eq!(
            parsed.items[2].authentication_type.as_deref(),
            Some("radius_connect")
        );
    }

    #[test]
    fn falls_back_to_top_level_authentication_when_sources_are_absent() {
        let response = Response::from(
            r#"<get_users_response status="200" status_text="OK">
                <user id="u-1"><name>Alice</name><authentication>file</authentication></user>
            </get_users_response>"#,
        );

        let parsed = GetUsersResponse::from_response(&response).expect("users parse");

        assert_eq!(parsed.items[0].authentication_type.as_deref(), Some("file"));
    }
}
