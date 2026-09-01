// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Credential response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_bool, parse_document, parse_entity_id, parse_entity_meta,
    status_from_response, ActionResponse, CountInfo, EntityMeta, ParseError,
};
use crate::{CredentialStoreCredentialType, CredentialType, GmpResponse, GmpVersion};

/// Credential kind observed in a `get_credentials` response.
///
/// The variants map every distinct wire value emitted by the typed credential
/// create APIs. GVMD uses `snmp` for both community-based SNMP and `SNMPv3`, so
/// an observation cannot distinguish those create-time variants from the type
/// code alone. Missing, malformed, and unknown values remain explicit so
/// consumers can fail closed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CredentialKind {
    /// Client certificate (`cc`).
    ClientCertificate,
    /// Kerberos 5 (`krb5`).
    Kerberos5,
    /// Password-only credential (`pw`).
    PasswordOnly,
    /// PGP encryption key (`pgp`).
    PgpEncryptionKey,
    /// S/MIME certificate (`smime`).
    SmimeCertificate,
    /// SNMP credential (`snmp`), whose protocol code does not identify its version.
    Snmp,
    /// Username and password (`up`).
    UsernamePassword,
    /// Username and SSH key (`usk`).
    UsernameSshKey,
    /// Credential-store-backed client certificate (`cs_cc`).
    CredentialStoreClientCertificate,
    /// Credential-store-backed password-only credential (`cs_pw`).
    CredentialStorePasswordOnly,
    /// Credential-store-backed PGP encryption key (`cs_pgp`).
    CredentialStorePgpEncryptionKey,
    /// Credential-store-backed S/MIME certificate (`cs_smime`).
    CredentialStoreSmimeCertificate,
    /// Credential-store-backed SNMP credential (`cs_snmp`).
    CredentialStoreSnmp,
    /// Credential-store-backed username and password (`cs_up`).
    CredentialStoreUsernamePassword,
    /// Credential-store-backed username and SSH key (`cs_usk`).
    CredentialStoreUsernameSshKey,
    /// The response omitted the `type` element.
    #[default]
    Missing,
    /// The response contained an empty, whitespace-padded, or whitespace-only value.
    Malformed(String),
    /// The response contained a well-formed but unsupported future value.
    Unknown(String),
}

impl CredentialKind {
    /// Parse an optional GMP credential type without defaulting missing or
    /// unrecognized values to a supported kind.
    #[must_use]
    pub fn from_optional_gmp_str(value: Option<&str>) -> Self {
        let Some(value) = value else {
            return Self::Missing;
        };
        if value.is_empty()
            || value.trim() != value
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Self::Malformed(value.to_string());
        }
        match value {
            "cc" => Self::ClientCertificate,
            "krb5" => Self::Kerberos5,
            "pw" => Self::PasswordOnly,
            "pgp" => Self::PgpEncryptionKey,
            "smime" => Self::SmimeCertificate,
            "snmp" => Self::Snmp,
            "up" => Self::UsernamePassword,
            "usk" => Self::UsernameSshKey,
            "cs_cc" => Self::CredentialStoreClientCertificate,
            "cs_pw" => Self::CredentialStorePasswordOnly,
            "cs_pgp" => Self::CredentialStorePgpEncryptionKey,
            "cs_smime" => Self::CredentialStoreSmimeCertificate,
            "cs_snmp" => Self::CredentialStoreSnmp,
            "cs_up" => Self::CredentialStoreUsernamePassword,
            "cs_usk" => Self::CredentialStoreUsernameSshKey,
            other => Self::Unknown(other.to_string()),
        }
    }
}

impl From<CredentialType> for CredentialKind {
    fn from(value: CredentialType) -> Self {
        match value {
            CredentialType::ClientCertificate => Self::ClientCertificate,
            CredentialType::Kerberos5 => Self::Kerberos5,
            CredentialType::PasswordOnly => Self::PasswordOnly,
            CredentialType::PgpEncryptionKey => Self::PgpEncryptionKey,
            CredentialType::SmimeCertificate => Self::SmimeCertificate,
            CredentialType::SnmpV1Or2c | CredentialType::SnmpV3 => Self::Snmp,
            CredentialType::UsernamePassword => Self::UsernamePassword,
            CredentialType::UsernameSshKey => Self::UsernameSshKey,
        }
    }
}

impl From<CredentialStoreCredentialType> for CredentialKind {
    fn from(value: CredentialStoreCredentialType) -> Self {
        match value {
            CredentialStoreCredentialType::ClientCertificate => {
                Self::CredentialStoreClientCertificate
            }
            CredentialStoreCredentialType::PasswordOnly => Self::CredentialStorePasswordOnly,
            CredentialStoreCredentialType::PgpEncryptionKey => {
                Self::CredentialStorePgpEncryptionKey
            }
            CredentialStoreCredentialType::SmimeCertificate => {
                Self::CredentialStoreSmimeCertificate
            }
            CredentialStoreCredentialType::Snmp => Self::CredentialStoreSnmp,
            CredentialStoreCredentialType::UsernamePassword => {
                Self::CredentialStoreUsernamePassword
            }
            CredentialStoreCredentialType::UsernameSshKey => Self::CredentialStoreUsernameSshKey,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Credential {
    pub meta: EntityMeta,
    /// Typed credential kind. Missing and unsupported values are explicit.
    #[cfg_attr(feature = "serde", serde(default))]
    pub kind: CredentialKind,
    /// Raw GMP type code retained for backward compatibility.
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
        let raw_type = node.child_raw_text("type");
        Ok(Self {
            meta: parse_entity_meta(node)?,
            kind: CredentialKind::from_optional_gmp_str(raw_type),
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

impl GmpResponse for GetCredentialsResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
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

impl GmpResponse for CreateCredentialResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

pub type VerifyCredentialStoreResponse = ActionResponse;

pub type ModifyCredentialResponse = ActionResponse;
pub type DeleteCredentialResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn maps_every_create_side_credential_type_code() {
        let cases = [
            ("cc", CredentialKind::ClientCertificate),
            ("krb5", CredentialKind::Kerberos5),
            ("pw", CredentialKind::PasswordOnly),
            ("pgp", CredentialKind::PgpEncryptionKey),
            ("smime", CredentialKind::SmimeCertificate),
            ("snmp", CredentialKind::Snmp),
            ("up", CredentialKind::UsernamePassword),
            ("usk", CredentialKind::UsernameSshKey),
            ("cs_cc", CredentialKind::CredentialStoreClientCertificate),
            ("cs_pw", CredentialKind::CredentialStorePasswordOnly),
            ("cs_pgp", CredentialKind::CredentialStorePgpEncryptionKey),
            ("cs_smime", CredentialKind::CredentialStoreSmimeCertificate),
            ("cs_snmp", CredentialKind::CredentialStoreSnmp),
            ("cs_up", CredentialKind::CredentialStoreUsernamePassword),
            ("cs_usk", CredentialKind::CredentialStoreUsernameSshKey),
        ];

        for (wire_value, expected) in cases {
            assert_eq!(
                CredentialKind::from_optional_gmp_str(Some(wire_value)),
                expected,
                "wire value {wire_value}"
            );
        }
    }

    #[test]
    fn maps_create_types_to_observed_kinds() {
        assert_eq!(
            CredentialKind::from(CredentialType::UsernamePassword),
            CredentialKind::UsernamePassword
        );
        assert_eq!(
            CredentialKind::from(CredentialType::SnmpV3),
            CredentialKind::Snmp
        );
        assert_eq!(
            CredentialKind::from(CredentialStoreCredentialType::UsernameSshKey),
            CredentialKind::CredentialStoreUsernameSshKey
        );
    }

    #[test]
    fn preserves_missing_malformed_and_unknown_types() {
        assert_eq!(
            CredentialKind::from_optional_gmp_str(None),
            CredentialKind::Missing
        );
        assert_eq!(
            CredentialKind::from_optional_gmp_str(Some("")),
            CredentialKind::Malformed(String::new())
        );
        assert_eq!(
            CredentialKind::from_optional_gmp_str(Some(" up ")),
            CredentialKind::Malformed(" up ".to_string())
        );
        assert_eq!(
            CredentialKind::from_optional_gmp_str(Some("future_kind")),
            CredentialKind::Unknown("future_kind".to_string())
        );
    }

    #[test]
    fn response_parsing_keeps_unsupported_type_states_distinct() {
        let response = Response::from(
            r#"<get_credentials_response status="200" status_text="OK">
                <credential id="missing"><name>Missing</name></credential>
                <credential id="empty"><name>Empty</name><type></type></credential>
                <credential id="padded"><name>Padded</name><type> up </type></credential>
                <credential id="reference"><name>Reference</name><type>&#x20;up&#x20;</type></credential>
                <credential id="cdata"><name>CDATA</name><type><![CDATA[ up ]]></type></credential>
                <credential id="invalid"><name>Invalid</name><type>UP!</type></credential>
                <credential id="unknown"><name>Unknown</name><type>future_kind</type></credential>
            </get_credentials_response>"#,
        );

        let parsed = GetCredentialsResponse::from_response(&response).expect("credentials parse");

        assert_eq!(parsed.items[0].kind, CredentialKind::Missing);
        assert_eq!(
            parsed.items[1].kind,
            CredentialKind::Malformed(String::new())
        );
        assert_eq!(
            parsed.items[2].kind,
            CredentialKind::Malformed(" up ".to_string())
        );
        assert_eq!(
            parsed.items[3].kind,
            CredentialKind::Malformed(" up ".to_string())
        );
        assert_eq!(
            parsed.items[4].kind,
            CredentialKind::Malformed(" up ".to_string())
        );
        assert_eq!(
            parsed.items[5].kind,
            CredentialKind::Malformed("UP!".to_string())
        );
        assert_eq!(
            parsed.items[6].kind,
            CredentialKind::Unknown("future_kind".to_string())
        );
    }

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
        assert_eq!(parsed.items[0].kind, CredentialKind::UsernamePassword);
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
        assert_eq!(cred.kind, CredentialKind::Missing);
        assert_eq!(cred.login, None);
        assert_eq!(cred.full_type, None);
        assert!(!cred.allow_insecure);
    }
}
