// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Filter response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_document, parse_entity_id, parse_entity_meta, status_from_response,
    ActionResponse, CountInfo, EntityMeta, ParseError,
};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Filter {
    pub meta: EntityMeta,
    pub type_: Option<String>,
    pub term: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetFiltersResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Filter>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateFilterResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl Filter {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            type_: node.optional_child_text("type"),
            term: node.optional_child_text("term"),
        })
    }
}

impl GetFiltersResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("filter")
            .map(Filter::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "filter_count")?,
        })
    }
}

impl GmpResponse for GetFiltersResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl CreateFilterResponse {
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

impl GmpResponse for CreateFilterResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

pub type ModifyFilterResponse = ActionResponse;
pub type DeleteFilterResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_filters() {
        let response = Response::from(
            r#"<get_filters_response status="200" status_text="OK">
                <filter id="f-1">
                    <owner><name>admin</name></owner>
                    <name>Filter One</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <type>task</type>
                    <term>rows=10 first=1 sort=name</term>
                </filter>
                <filter id="f-2">
                    <name>Filter Two</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                    <type>alert</type>
                </filter>
                <filter_count>2<filtered>2</filtered><page>1</page></filter_count>
            </get_filters_response>"#,
        );

        let parsed = GetFiltersResponse::from_response(&response).expect("filters parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].type_.as_deref(), Some("task"));
        assert_eq!(
            parsed.items[0].term.as_deref(),
            Some("rows=10 first=1 sort=name")
        );
        assert_eq!(parsed.items[1].type_.as_deref(), Some("alert"));
        assert!(parsed.items[1].meta.in_use);
    }

    #[test]
    fn parses_empty_filters() {
        let response = Response::from(
            r#"<get_filters_response status="200" status_text="OK"><filter_count>0<filtered>0</filtered></filter_count></get_filters_response>"#,
        );

        let parsed = GetFiltersResponse::from_response(&response).expect("filters parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_filter_response() {
        let response = Response::from(
            r#"<create_filter_response status="201" status_text="OK, resource created" id="f-1"/>"#,
        );

        let parsed = CreateFilterResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "f-1");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_filters_response status="400" status_text="Bad request"/>"#);

        let error = GetFiltersResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }

    #[test]
    fn parses_missing_optional_filter_fields() {
        let response = Response::from(
            r#"<get_filters_response status="200" status_text="OK">
                <filter id="f-1">
                    <name>Only Required</name>
                </filter>
            </get_filters_response>"#,
        );

        let parsed = GetFiltersResponse::from_response(&response).expect("filters parse");
        let filter = &parsed.items[0];

        assert_eq!(filter.meta.comment, None);
        assert_eq!(filter.type_, None);
        assert_eq!(filter.term, None);
    }
}
