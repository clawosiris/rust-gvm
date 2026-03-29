// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Tag response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_bool, parse_document, parse_entity_id, parse_entity_meta, parse_u32,
    status_from_response, ActionResponse, CountInfo, EntityMeta, ParseError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Tag {
    pub meta: EntityMeta,
    pub value: Option<String>,
    pub resource_type: Option<String>,
    pub resource_count: Option<u32>,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetTagsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Tag>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateTagResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl Tag {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            value: node.optional_child_text("value"),
            resource_type: node
                .child("resources")
                .and_then(|r| r.optional_child_text("type")),
            resource_count: node
                .child("resources")
                .and_then(|r| r.child("count"))
                .and_then(|c| c.optional_child_text("total"))
                .map(|v| parse_u32(&v, "resource_count"))
                .transpose()?,
            active: node
                .optional_child_text("active")
                .map(|value| parse_bool(&value, "active"))
                .transpose()?
                .unwrap_or(false),
        })
    }
}

impl GetTagsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("tag")
            .map(Tag::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "tag_count")?,
        })
    }
}

impl CreateTagResponse {
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

pub type ModifyTagResponse = ActionResponse;
pub type DeleteTagResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_tags() {
        let response = Response::from(
            r#"<get_tags_response status="200" status_text="OK">
                <tag id="t-1">
                    <owner><name>admin</name></owner>
                    <name>Tag One</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <value>production</value>
                    <resources>
                        <type>task</type>
                        <count><total>5</total></count>
                    </resources>
                    <active>1</active>
                </tag>
                <tag id="t-2">
                    <name>Tag Two</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                    <active>0</active>
                </tag>
                <tag_count>2<filtered>2</filtered><page>1</page></tag_count>
            </get_tags_response>"#,
        );

        let parsed = GetTagsResponse::from_response(&response).expect("tags parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].value.as_deref(), Some("production"));
        assert_eq!(parsed.items[0].resource_type.as_deref(), Some("task"));
        assert_eq!(parsed.items[0].resource_count, Some(5));
        assert!(parsed.items[0].active);
        assert!(!parsed.items[1].active);
        assert!(parsed.items[1].meta.in_use);
    }

    #[test]
    fn parses_empty_tags() {
        let response = Response::from(
            r#"<get_tags_response status="200" status_text="OK"><tag_count>0<filtered>0</filtered></tag_count></get_tags_response>"#,
        );

        let parsed = GetTagsResponse::from_response(&response).expect("tags parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_tag_response() {
        let response = Response::from(
            r#"<create_tag_response status="201" status_text="OK, resource created" id="t-1"/>"#,
        );

        let parsed = CreateTagResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "t-1");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_tags_response status="400" status_text="Bad request"/>"#);

        let error = GetTagsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }

    #[test]
    fn parses_missing_optional_tag_fields() {
        let response = Response::from(
            r#"<get_tags_response status="200" status_text="OK">
                <tag id="t-1">
                    <name>Only Required</name>
                </tag>
            </get_tags_response>"#,
        );

        let parsed = GetTagsResponse::from_response(&response).expect("tags parse");
        let tag = &parsed.items[0];

        assert_eq!(tag.meta.comment, None);
        assert_eq!(tag.value, None);
        assert_eq!(tag.resource_type, None);
        assert_eq!(tag.resource_count, None);
        assert!(!tag.active);
    }
}
