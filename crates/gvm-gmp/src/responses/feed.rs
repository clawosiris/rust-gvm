// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Feed response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_bool, parse_document, status_from_response, CountInfo, ParseError, XmlNode,
};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Feed {
    pub type_: String,
    pub name: String,
    pub version: String,
    pub status: Option<String>,
    pub description: Option<String>,
    pub sync_not_available: Option<String>,
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
    pub feed_owner_set: bool,
    pub feed_roles_set: bool,
    pub feed_resources_access: bool,
}

impl Feed {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        let sync_not_available = node
            .child("sync_not_available")
            .map(|sync| sync.required_child_text("error"))
            .transpose()?;
        let currently_syncing = node
            .child("currently_syncing")
            .map(|sync| {
                if sync.child("timestamp").is_some() {
                    sync.required_child_text("timestamp")
                } else if !sync.text.is_empty() {
                    Ok(sync.text.clone())
                } else {
                    Err(ParseError::MissingElement("timestamp".to_string()))
                }
            })
            .transpose()?;
        Ok(Self {
            type_: node.required_child_text("type")?,
            name: node.required_child_text("name")?,
            version: node.required_child_text("version")?,
            status: node.optional_child_text("status"),
            description: node.optional_child_text("description"),
            sync_not_available,
            currently_syncing,
        })
    }
}

fn optional_bool_child(root: &XmlNode, name: &str) -> Result<bool, ParseError> {
    root.child_text(name)
        .map_or(Ok(false), |value| parse_bool(&value, name))
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
            feed_owner_set: optional_bool_child(&root, "feed_owner_set")?,
            feed_roles_set: optional_bool_child(&root, "feed_roles_set")?,
            feed_resources_access: optional_bool_child(&root, "feed_resources_access")?,
        })
    }
}

impl GmpResponse for GetFeedsResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
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
                <feed_owner_set>1</feed_owner_set>
                <feed_roles_set>0</feed_roles_set>
                <feed_resources_access>true</feed_resources_access>
                <feed>
                    <type>NVT</type>
                    <name>NVT Feed</name>
                    <version>202603260800</version>
                    <description>Network vulnerability tests</description>
                    <currently_syncing><timestamp></timestamp></currently_syncing>
                </feed>
                <feed>
                    <type>SCAP</type>
                    <name>SCAP Feed</name>
                    <version>202603250700</version>
                    <description>Security content automation data</description>
                    <sync_not_available><error>Feed lock unavailable</error></sync_not_available>
                </feed>
            </get_feeds_response>"#,
        );

        let parsed = GetFeedsResponse::from_response(&response).expect("feeds parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts, CountInfo::default());
        assert!(parsed.feed_owner_set);
        assert!(!parsed.feed_roles_set);
        assert!(parsed.feed_resources_access);
        assert_eq!(parsed.items[0].type_, "NVT");
        assert_eq!(parsed.items[0].currently_syncing.as_deref(), Some(""));
        assert_eq!(
            parsed.items[1].sync_not_available.as_deref(),
            Some("Feed lock unavailable")
        );
    }

    #[test]
    fn parses_empty_feeds() {
        let response = Response::from(
            r#"<get_feeds_response status="200" status_text="OK">
                <feed_owner_set>0</feed_owner_set>
                <feed_roles_set>0</feed_roles_set>
                <feed_resources_access>0</feed_resources_access>
                <feed_count>0<filtered>0</filtered></feed_count>
            </get_feeds_response>"#,
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
    fn parses_missing_optional_non_version_feed_fields() {
        let response = Response::from(
            r#"<get_feeds_response status="200" status_text="OK">
                <feed_owner_set>1</feed_owner_set>
                <feed_roles_set>1</feed_roles_set>
                <feed_resources_access>1</feed_resources_access>
                <feed>
                    <type>CERT</type>
                    <name>CERT Feed</name>
                    <version>202603260800</version>
                </feed>
            </get_feeds_response>"#,
        );

        let parsed = GetFeedsResponse::from_response(&response).expect("feeds parse");
        let feed = &parsed.items[0];

        assert_eq!(feed.version, "202603260800");
        assert_eq!(feed.status, None);
        assert_eq!(feed.description, None);
        assert_eq!(feed.sync_not_available, None);
        assert_eq!(feed.currently_syncing, None);
    }

    #[test]
    fn preserves_legacy_direct_sync_value() {
        let response = Response::from(
            r#"<get_feeds_response status="200" status_text="OK">
                <feed>
                    <type>NVT</type>
                    <name>NVT Feed</name>
                    <version>202603260800</version>
                    <currently_syncing>0</currently_syncing>
                </feed>
            </get_feeds_response>"#,
        );

        let parsed = GetFeedsResponse::from_response(&response).expect("legacy sync value parses");

        assert_eq!(parsed.items[0].currently_syncing.as_deref(), Some("0"));
        assert!(!parsed.feed_owner_set);
        assert!(!parsed.feed_roles_set);
        assert!(!parsed.feed_resources_access);
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
        let missing_version = Response::from(
            r#"<get_feeds_response status="200" status_text="OK">
                <feed><type>NVT</type><name>NVT Feed</name></feed>
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
        assert!(matches!(
            GetFeedsResponse::from_response(&missing_version),
            Err(ParseError::MissingElement(field)) if field == "version"
        ));
    }

    #[test]
    fn rejects_invalid_access_flag_and_incomplete_sync_state() {
        let invalid_flag = Response::from(
            r#"<get_feeds_response status="200" status_text="OK">
                <feed_owner_set>sometimes</feed_owner_set>
            </get_feeds_response>"#,
        );
        assert!(matches!(
            GetFeedsResponse::from_response(&invalid_flag),
            Err(ParseError::InvalidValue { field, value })
                if field == "feed_owner_set" && value == "sometimes"
        ));

        let missing_flag = Response::from(
            r#"<get_feeds_response status="200" status_text="OK">
                <feed_owner_set>1</feed_owner_set>
                <feed_roles_set>1</feed_roles_set>
            </get_feeds_response>"#,
        );
        let parsed = GetFeedsResponse::from_response(&missing_flag).expect("missing flag defaults");
        assert!(parsed.feed_owner_set);
        assert!(parsed.feed_roles_set);
        assert!(!parsed.feed_resources_access);

        let missing_timestamp = Response::from(
            r#"<get_feeds_response status="200" status_text="OK">
                <feed_owner_set>1</feed_owner_set>
                <feed_roles_set>1</feed_roles_set>
                <feed_resources_access>1</feed_resources_access>
                <feed>
                    <type>NVT</type><name>NVT Feed</name><version>1</version>
                    <currently_syncing/>
                </feed>
            </get_feeds_response>"#,
        );
        assert!(matches!(
            GetFeedsResponse::from_response(&missing_timestamp),
            Err(ParseError::MissingElement(field)) if field == "timestamp"
        ));
    }
}
