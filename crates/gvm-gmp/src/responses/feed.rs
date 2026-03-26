// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Feed response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_document, status_from_response, CountInfo, ParseError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Feed {
    pub type_: String,
    pub name: String,
    pub version: Option<String>,
    pub status: Option<String>,
    pub description: Option<String>,
    pub currently_syncing: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetFeedsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Feed>,
    pub counts: CountInfo,
}

impl Feed {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            type_: node.required_child_text("type")?,
            name: node.required_child_text("name")?,
            version: node.optional_child_text("version"),
            status: node.optional_child_text("status"),
            description: node.optional_child_text("description"),
            currently_syncing: node.optional_child_text("currently_syncing"),
        })
    }
}

impl GetFeedsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("feed")
            .map(Feed::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "feed_count")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_feeds() {
        let response = Response::from(
            r#"<get_feeds_response status="200" status_text="OK">
                <feed>
                    <type>NVT</type>
                    <name>NVT Feed</name>
                    <version>202603260800</version>
                    <status>Current</status>
                    <description>Network vulnerability tests</description>
                    <currently_syncing>0</currently_syncing>
                </feed>
                <feed>
                    <type>SCAP</type>
                    <name>SCAP Feed</name>
                    <version>202603250700</version>
                    <status>Updating</status>
                    <description>Security content automation data</description>
                    <currently_syncing>1</currently_syncing>
                </feed>
                <feed_count>2<filtered>2</filtered><page>1</page></feed_count>
            </get_feeds_response>"#,
        );

        let parsed = GetFeedsResponse::from_response(&response).expect("feeds parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].type_, "NVT");
        assert_eq!(parsed.items[1].currently_syncing.as_deref(), Some("1"));
    }

    #[test]
    fn parses_empty_feeds() {
        let response = Response::from(
            r#"<get_feeds_response status="200" status_text="OK"><feed_count>0<filtered>0</filtered></feed_count></get_feeds_response>"#,
        );

        let parsed = GetFeedsResponse::from_response(&response).expect("feeds parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_feeds_response status="500" status_text="Internal Error"/>"#);

        let error = GetFeedsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 500,
                message
            } if message == "Internal Error"
        ));
    }

    #[test]
    fn parses_missing_optional_feed_fields() {
        let response = Response::from(
            r#"<get_feeds_response status="200" status_text="OK">
                <feed>
                    <type>CERT</type>
                    <name>CERT Feed</name>
                </feed>
            </get_feeds_response>"#,
        );

        let parsed = GetFeedsResponse::from_response(&response).expect("feeds parse");
        let feed = &parsed.items[0];

        assert_eq!(feed.version, None);
        assert_eq!(feed.status, None);
        assert_eq!(feed.description, None);
        assert_eq!(feed.currently_syncing, None);
    }

    #[test]
    fn rejects_missing_required_feed_fields() {
        let missing_type = Response::from(
            r#"<get_feeds_response status="200" status_text="OK">
                <feed><name>Feed Without Type</name></feed>
            </get_feeds_response>"#,
        );
        let missing_name = Response::from(
            r#"<get_feeds_response status="200" status_text="OK">
                <feed><type>NVT</type></feed>
            </get_feeds_response>"#,
        );

        assert!(matches!(
            GetFeedsResponse::from_response(&missing_type),
            Err(ParseError::MissingElement(field)) if field == "type"
        ));
        assert!(matches!(
            GetFeedsResponse::from_response(&missing_name),
            Err(ParseError::MissingElement(field)) if field == "name"
        ));
    }
}
