// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Permission response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_document, parse_entity_id, parse_entity_meta, parse_named_entity,
    status_from_response, ActionResponse, CountInfo, EntityMeta, NamedEntity, ParseError,
};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Permission {
    pub meta: EntityMeta,
    pub subject_type: Option<String>,
    pub subject: Option<NamedEntity>,
    pub resource_type: Option<String>,
    pub resource: Option<NamedEntity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetPermissionsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Permission>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreatePermissionResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl Permission {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            subject_type: node
                .child("subject")
                .and_then(|s| s.optional_child_text("type")),
            subject: parse_named_entity(node, "subject")?,
            resource_type: node
                .child("resource")
                .and_then(|r| r.optional_child_text("type")),
            resource: parse_named_entity(node, "resource")?,
        })
    }
}

impl GetPermissionsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("permission")
            .map(Permission::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "permission_count")?,
        })
    }
}

impl GmpResponse for GetPermissionsResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl CreatePermissionResponse {
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

impl GmpResponse for CreatePermissionResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

pub type ModifyPermissionResponse = ActionResponse;
pub type DeletePermissionResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_permissions() {
        let response = Response::from(
            r#"<get_permissions_response status="200" status_text="OK">
                <permission id="p-1">
                    <owner><name>admin</name></owner>
                    <name>get_tasks</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <subject id="u-1">
                        <name>User One</name>
                        <type>user</type>
                    </subject>
                    <resource id="t-1">
                        <name>Task One</name>
                        <type>task</type>
                    </resource>
                </permission>
                <permission id="p-2">
                    <name>get_alerts</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                </permission>
                <permission_count>2<filtered>2</filtered><page>1</page></permission_count>
            </get_permissions_response>"#,
        );

        let parsed = GetPermissionsResponse::from_response(&response).expect("permissions parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].subject_type.as_deref(), Some("user"));
        assert_eq!(
            parsed.items[0].subject.as_ref().map(|s| s.name.as_str()),
            Some("User One")
        );
        assert_eq!(parsed.items[0].resource_type.as_deref(), Some("task"));
        assert_eq!(
            parsed.items[0].resource.as_ref().map(|r| r.name.as_str()),
            Some("Task One")
        );
        assert!(parsed.items[1].meta.in_use);
    }

    #[test]
    fn parses_empty_permissions() {
        let response = Response::from(
            r#"<get_permissions_response status="200" status_text="OK"><permission_count>0<filtered>0</filtered></permission_count></get_permissions_response>"#,
        );

        let parsed = GetPermissionsResponse::from_response(&response).expect("permissions parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_permission_response() {
        let response = Response::from(
            r#"<create_permission_response status="201" status_text="OK, resource created" id="p-1"/>"#,
        );

        let parsed = CreatePermissionResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "p-1");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_permissions_response status="400" status_text="Bad request"/>"#);

        let error = GetPermissionsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }

    #[test]
    fn parses_missing_optional_permission_fields() {
        let response = Response::from(
            r#"<get_permissions_response status="200" status_text="OK">
                <permission id="p-1">
                    <name>get_tasks</name>
                </permission>
            </get_permissions_response>"#,
        );

        let parsed = GetPermissionsResponse::from_response(&response).expect("permissions parse");
        let perm = &parsed.items[0];

        assert_eq!(perm.meta.comment, None);
        assert_eq!(perm.subject_type, None);
        assert_eq!(perm.subject, None);
        assert_eq!(perm.resource_type, None);
        assert_eq!(perm.resource, None);
    }
}
