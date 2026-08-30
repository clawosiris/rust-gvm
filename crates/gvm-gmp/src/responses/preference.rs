// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Preference response models.

use gvm_protocol::Response;

use crate::responses::common::{parse_document, status_from_response, ParseError};

/// NVT reference attached to a configured preference.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PreferenceNvt {
    pub oid: String,
    pub name: Option<String>,
}

/// Scanner or NVT preference returned by `get_preferences`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Preference {
    pub nvt: Option<PreferenceNvt>,
    pub name: String,
    pub id: Option<String>,
    pub type_: Option<String>,
    pub value: Option<String>,
    pub alternatives: Vec<String>,
    pub default: Option<String>,
}

/// Typed `get_preferences` response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetPreferencesResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Preference>,
}

impl Preference {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        let nvt = node
            .child("nvt")
            .map(|nvt| -> Result<PreferenceNvt, ParseError> {
                Ok(PreferenceNvt {
                    oid: nvt
                        .attr("oid")
                        .ok_or_else(|| ParseError::MissingElement("preference.nvt.oid".into()))?
                        .to_string(),
                    name: nvt.optional_child_text("name"),
                })
            })
            .transpose()?;

        Ok(Self {
            nvt,
            name: node.required_child_text("name")?,
            id: node.optional_child_text("id"),
            type_: node.optional_child_text("type"),
            value: node.child_text("value"),
            alternatives: node
                .children_named("alt")
                .map(|alternative| alternative.text.clone())
                .collect(),
            default: node.child_text("default"),
        })
    }
}

impl GetPreferencesResponse {
    /// Parses a typed preference response from the GMP response envelope.
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("preference")
            .map(Preference::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
        })
    }
}

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_default_and_configured_preferences() {
        let response = Response::from(
            r#"<get_preferences_response status="200" status_text="OK">
                <preference>
                    <name>1.3.6.1:1:entry:Timeout</name>
                    <value>5</value>
                    <default>5</default>
                </preference>
                <preference>
                    <nvt oid="1.3.6.1"><name>Services</name></nvt>
                    <id>1</id>
                    <name>Timeout</name>
                    <type>entry</type>
                    <value></value>
                    <alt>5</alt>
                    <alt>10</alt>
                    <default>5</default>
                </preference>
            </get_preferences_response>"#,
        );

        let parsed = GetPreferencesResponse::from_response(&response).expect("preferences parse");
        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.items[0].value.as_deref(), Some("5"));
        assert_eq!(parsed.items[0].nvt, None);
        assert_eq!(
            parsed.items[1]
                .nvt
                .as_ref()
                .expect("configured preference NVT")
                .oid,
            "1.3.6.1"
        );
        assert_eq!(parsed.items[1].id.as_deref(), Some("1"));
        assert_eq!(parsed.items[1].type_.as_deref(), Some("entry"));
        assert_eq!(parsed.items[1].value.as_deref(), Some(""));
        assert_eq!(parsed.items[1].alternatives, ["5", "10"]);
    }

    #[test]
    fn accepts_empty_preference_catalog() {
        let response =
            Response::from(r#"<get_preferences_response status="200" status_text="OK"/>"#);
        let parsed = GetPreferencesResponse::from_response(&response).expect("empty response");
        assert!(parsed.items.is_empty());
    }

    #[test]
    fn rejects_missing_name_and_server_errors() {
        let missing_name = Response::from(
            r#"<get_preferences_response status="200" status_text="OK"><preference/></get_preferences_response>"#,
        );
        assert!(matches!(
            GetPreferencesResponse::from_response(&missing_name),
            Err(ParseError::MissingElement(name)) if name == "name"
        ));

        let server_error = Response::from(
            r#"<get_preferences_response status="503" status_text="Feed unavailable"/>"#,
        );
        assert!(matches!(
            GetPreferencesResponse::from_response(&server_error),
            Err(ParseError::ServerError { status: 503, message }) if message == "Feed unavailable"
        ));
    }
}
