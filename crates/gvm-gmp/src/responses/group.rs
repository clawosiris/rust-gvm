// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Group response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_csv_list, parse_document, parse_entity_id, parse_entity_meta,
    status_from_response, ActionResponse, CountInfo, EntityMeta, ParseError,
};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Group {
    pub meta: EntityMeta,
    pub users: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetGroupsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Group>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateGroupResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl Group {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            users: node
                .optional_child_text("users")
                .map(|value| parse_csv_list(&value))
                .unwrap_or_default(),
        })
    }
}

impl GetGroupsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("group")
            .map(Group::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "group_count")?,
        })
    }
}

impl GmpResponse for GetGroupsResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl CreateGroupResponse {
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

impl GmpResponse for CreateGroupResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

pub type ModifyGroupResponse = ActionResponse;
pub type DeleteGroupResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_groups() {
        let response = Response::from(
            r#"<get_groups_response status="200" status_text="OK">
                <group id="g-1">
                    <owner><name>admin</name></owner>
                    <name>Group One</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <users>alice, bob, ,charlie</users>
                </group>
                <group id="g-2">
                    <name>Group Two</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                </group>
                <group_count>2<filtered>2</filtered><page>1</page></group_count>
            </get_groups_response>"#,
        );

        let parsed = GetGroupsResponse::from_response(&response).expect("groups parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(
            parsed.items[0].users,
            vec![
                "alice".to_string(),
                "bob".to_string(),
                "charlie".to_string()
            ]
        );
        assert_eq!(
            parsed.items[0].meta.owner.as_ref().map(|o| o.name.as_str()),
            Some("admin")
        );
        assert!(parsed.items[1].meta.in_use);
    }

    #[test]
    fn parses_empty_groups() {
        let response = Response::from(
            r#"<get_groups_response status="200" status_text="OK"><group_count>0<filtered>0</filtered></group_count></get_groups_response>"#,
        );

        let parsed = GetGroupsResponse::from_response(&response).expect("groups parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_group_response() {
        let response = Response::from(
            r#"<create_group_response status="201" status_text="OK, resource created" id="g-1"/>"#,
        );

        let parsed = CreateGroupResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "g-1");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_groups_response status="400" status_text="Bad request"/>"#);

        let error = GetGroupsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }

    #[test]
    fn parses_missing_optional_group_fields() {
        let response = Response::from(
            r#"<get_groups_response status="200" status_text="OK">
                <group id="g-1">
                    <name>Only Required</name>
                </group>
            </get_groups_response>"#,
        );

        let parsed = GetGroupsResponse::from_response(&response).expect("groups parse");
        let group = &parsed.items[0];

        assert_eq!(group.meta.comment, None);
        assert!(group.users.is_empty());
    }
}
