// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Credential response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_bool, parse_document, parse_entity_id, parse_entity_meta,
    status_from_response, ActionResponse, CountInfo, EntityMeta, ParseError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Credential {
    pub meta: EntityMeta,
    pub type_: Option<String>,
    pub login: Option<String>,
    pub full_type: Option<String>,
    pub allow_insecure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetCredentialsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Credential>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CredentialStore {
    pub id: Option<String>,
    pub name: String,
    pub type_: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetCredentialStoresResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<CredentialStore>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateCredentialResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl Credential {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            type_: node.optional_child_text("type"),
            login: node.optional_child_text("login"),
            full_type: node.optional_child_text("full_type"),
            allow_insecure: node
                .optional_child_text("allow_insecure")
                .map(|value| parse_bool(&value, "allow_insecure"))
                .transpose()?
                .unwrap_or(false),
        })
    }
}

impl GetCredentialsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("credential")
            .map(Credential::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "credential_count")?,
        })
    }
}

impl CredentialStore {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            id: node.attr("id").map(ToString::to_string),
            name: node.required_child_text("name")?,
            type_: node.optional_child_text("type"),
        })
    }
}

impl GetCredentialStoresResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("credential_store")
            .map(CredentialStore::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "credential_store_count")?,
        })
    }
}

impl CreateCredentialResponse {
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

pub type ModifyCredentialResponse = ActionResponse;
pub type DeleteCredentialResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_credentials() {
        let response = Response::from(
            r#"<get_credentials_response status="200" status_text="OK">
                <credential id="c-1">
                    <owner><name>admin</name></owner>
                    <name>Cred One</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <type>up</type>
                    <login>admin</login>
                    <full_type>Username + Password</full_type>
                    <allow_insecure>1</allow_insecure>
                </credential>
                <credential id="c-2">
                    <name>Cred Two</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                    <allow_insecure>0</allow_insecure>
                </credential>
                <credential_count>2<filtered>2</filtered><page>1</page></credential_count>
            </get_credentials_response>"#,
        );

        let parsed = GetCredentialsResponse::from_response(&response).expect("credentials parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].type_.as_deref(), Some("up"));
        assert_eq!(parsed.items[0].login.as_deref(), Some("admin"));
        assert_eq!(
            parsed.items[0].full_type.as_deref(),
            Some("Username + Password")
        );
        assert!(parsed.items[0].allow_insecure);
        assert!(!parsed.items[1].allow_insecure);
        assert!(parsed.items[1].meta.in_use);
    }

    #[test]
    fn parses_empty_credentials() {
        let response = Response::from(
            r#"<get_credentials_response status="200" status_text="OK"><credential_count>0<filtered>0</filtered></credential_count></get_credentials_response>"#,
        );

        let parsed = GetCredentialsResponse::from_response(&response).expect("credentials parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_credential_stores() {
        let response = Response::from(
            r#"<get_credential_stores_response status="200" status_text="OK">
                <credential_store id="store-1"><name>Default store</name><type>local</type></credential_store>
                <credential_store_count>1<filtered>1</filtered></credential_store_count>
            </get_credential_stores_response>"#,
        );

        let parsed =
            GetCredentialStoresResponse::from_response(&response).expect("credential stores parse");

        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.items[0].name, "Default store");
        assert_eq!(parsed.items[0].type_.as_deref(), Some("local"));
        assert_eq!(parsed.counts.total, Some(1));
    }

    #[test]
    fn parses_create_credential_response() {
        let response = Response::from(
            r#"<create_credential_response status="201" status_text="OK, resource created" id="c-1"/>"#,
        );

        let parsed = CreateCredentialResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "c-1");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_credentials_response status="400" status_text="Bad request"/>"#);

        let error = GetCredentialsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }

    #[test]
    fn parses_missing_optional_credential_fields() {
        let response = Response::from(
            r#"<get_credentials_response status="200" status_text="OK">
                <credential id="c-1">
                    <name>Only Required</name>
                </credential>
            </get_credentials_response>"#,
        );

        let parsed = GetCredentialsResponse::from_response(&response).expect("credentials parse");
        let cred = &parsed.items[0];

        assert_eq!(cred.meta.comment, None);
        assert_eq!(cred.type_, None);
        assert_eq!(cred.login, None);
        assert_eq!(cred.full_type, None);
        assert!(!cred.allow_insecure);
    }
}
