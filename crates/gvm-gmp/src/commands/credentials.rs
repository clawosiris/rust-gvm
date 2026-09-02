// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Credential command builders.

use std::fmt;

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::{
    CredentialFormat, CredentialStoreCredentialType, CredentialType, SnmpAuthAlgorithm,
    SnmpPrivacyAlgorithm,
};
use crate::responses::{
    CreateCredentialResponse, DeleteCredentialResponse, GetCredentialStoresResponse,
    GetCredentialsResponse, ModifyCredentialResponse, ModifyCredentialStoreResponse,
    VerifyCredentialStoreResponse,
};
use crate::types::EntityId;
use crate::GmpRequest;

/// Optional fields for credential create requests.
#[derive(Clone, Default)]
pub struct CredentialOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional credential type.
    pub credential_type: Option<CredentialType>,
    /// Optional login or username value.
    pub login: Option<String>,
    /// Optional password value.
    pub password: Option<String>,
    /// Optional private key material.
    pub private_key: Option<String>,
    /// Optional private-key passphrase.
    pub key_phrase: Option<String>,
    /// Optional public key material.
    pub public_key: Option<String>,
    /// Optional certificate data.
    pub certificate: Option<String>,
    /// Optional SNMP community value.
    pub community: Option<String>,
    /// Optional SNMP authentication algorithm.
    pub auth_algorithm: Option<SnmpAuthAlgorithm>,
    /// Optional SNMP privacy password.
    pub privacy_password: Option<String>,
    /// Optional SNMP privacy algorithm.
    pub privacy_algorithm: Option<SnmpPrivacyAlgorithm>,
    /// Whether the credential may be used over an insecure transport.
    pub allow_insecure: Option<bool>,
    /// Deprecated comma-separated Kerberos KDC value accepted by gvmd.
    ///
    /// Prefer [`Self::kdcs`].
    pub kdc: Option<String>,
    /// Kerberos key distribution centers.
    pub kdcs: Vec<String>,
    /// Optional Kerberos realm.
    pub realm: Option<String>,
    /// Historical credential format field.
    ///
    /// Current gvmd does not consume `<format>` in create or modify credential
    /// requests. This value is retained for source compatibility but is not
    /// emitted.
    #[deprecated(note = "current gvmd ignores credential request format")]
    pub format: Option<CredentialFormat>,
}

/// Optional fields for `modify_credential` requests.
#[derive(Clone, Default)]
pub struct ModifyCredentialOpts {
    /// Optional replacement credential name.
    pub name: Option<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional login or username value.
    pub login: Option<String>,
    /// Optional password value.
    pub password: Option<String>,
    /// Optional private key material.
    pub private_key: Option<String>,
    /// Optional private-key passphrase.
    pub key_phrase: Option<String>,
    /// Optional public key material.
    pub public_key: Option<String>,
    /// Optional certificate data.
    pub certificate: Option<String>,
    /// Optional SNMP community value.
    pub community: Option<String>,
    /// Optional SNMP authentication algorithm.
    pub auth_algorithm: Option<SnmpAuthAlgorithm>,
    /// Optional SNMP privacy password.
    pub privacy_password: Option<String>,
    /// Optional SNMP privacy algorithm.
    pub privacy_algorithm: Option<SnmpPrivacyAlgorithm>,
    /// Whether the credential may be used over an insecure transport.
    pub allow_insecure: Option<bool>,
    /// Deprecated comma-separated Kerberos KDC value accepted by gvmd.
    ///
    /// Prefer [`Self::kdcs`].
    pub kdc: Option<String>,
    /// Kerberos key distribution centers.
    pub kdcs: Vec<String>,
    /// Optional Kerberos realm.
    pub realm: Option<String>,
}

#[allow(deprecated)]
impl From<CredentialOpts> for ModifyCredentialOpts {
    fn from(opts: CredentialOpts) -> Self {
        Self {
            name: None,
            comment: opts.comment,
            login: opts.login,
            password: opts.password,
            private_key: opts.private_key,
            key_phrase: opts.key_phrase,
            public_key: opts.public_key,
            certificate: opts.certificate,
            community: opts.community,
            auth_algorithm: opts.auth_algorithm,
            privacy_password: opts.privacy_password,
            privacy_algorithm: opts.privacy_algorithm,
            allow_insecure: opts.allow_insecure,
            kdc: opts.kdc,
            kdcs: opts.kdcs,
            realm: opts.realm,
        }
    }
}

fn redacted(value: &Option<String>) -> Option<&'static str> {
    value.as_ref().map(|_| "<redacted>")
}

fn present(value: &Option<String>) -> Option<&'static str> {
    value.as_ref().map(|_| "<present>")
}

impl fmt::Debug for CredentialOpts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialOpts")
            .field("comment", &self.comment)
            .field("credential_type", &self.credential_type)
            .field("login", &self.login)
            .field("password", &redacted(&self.password))
            .field("private_key", &redacted(&self.private_key))
            .field("key_phrase", &redacted(&self.key_phrase))
            .field("public_key", &present(&self.public_key))
            .field("certificate", &present(&self.certificate))
            .field("community", &redacted(&self.community))
            .field("auth_algorithm", &self.auth_algorithm)
            .field("privacy_password", &redacted(&self.privacy_password))
            .field("privacy_algorithm", &self.privacy_algorithm)
            .field("allow_insecure", &self.allow_insecure)
            .field("kdc", &self.kdc)
            .field("kdcs", &self.kdcs)
            .field("realm", &self.realm)
            .field("format", &"<ignored>")
            .finish()
    }
}

impl fmt::Debug for ModifyCredentialOpts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModifyCredentialOpts")
            .field("name", &self.name)
            .field("comment", &self.comment)
            .field("login", &self.login)
            .field("password", &redacted(&self.password))
            .field("private_key", &redacted(&self.private_key))
            .field("key_phrase", &redacted(&self.key_phrase))
            .field("public_key", &present(&self.public_key))
            .field("certificate", &present(&self.certificate))
            .field("community", &redacted(&self.community))
            .field("auth_algorithm", &self.auth_algorithm)
            .field("privacy_password", &redacted(&self.privacy_password))
            .field("privacy_algorithm", &self.privacy_algorithm)
            .field("allow_insecure", &self.allow_insecure)
            .field("kdc", &self.kdc)
            .field("kdcs", &self.kdcs)
            .field("realm", &self.realm)
            .finish()
    }
}

/// Optional fields for credential-store-backed credential creation.
#[derive(Debug, Clone, Default)]
pub struct CredentialStoreCredentialOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional credential store identifier.
    pub credential_store_id: Option<EntityId>,
}

/// Options for `get_credentials` requests.
#[derive(Debug, Clone, Default)]
pub struct GetCredentialsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Semantic request for listing credentials.
///
/// The associated response is fixed at compile time:
///
/// ```compile_fail
/// use gvm_gmp::commands::credentials::{GetCredentialsOpts, GetCredentialsRequest};
/// use gvm_gmp::responses::CreateCredentialResponse;
/// use gvm_gmp::GmpRequest;
///
/// fn require_create<R: GmpRequest<Response = CreateCredentialResponse>>(_: R) {}
/// require_create(GetCredentialsRequest::new(GetCredentialsOpts::default()));
/// ```
#[derive(Debug, Clone, Default)]
pub struct GetCredentialsRequest {
    opts: GetCredentialsOpts,
}

impl GetCredentialsRequest {
    /// Create a credential list request.
    #[must_use]
    pub fn new(opts: GetCredentialsOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetCredentialsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_credentials(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetCredentialsRequest {
    type Response = GetCredentialsResponse;
}

/// Semantic request for one detailed credential.
#[derive(Debug, Clone)]
pub struct GetCredentialRequest {
    credential_id: EntityId,
}

impl GetCredentialRequest {
    /// Create a detailed single-credential request.
    #[must_use]
    pub fn new(credential_id: EntityId) -> Self {
        Self { credential_id }
    }
}

impl Request for GetCredentialRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_credential(&self.credential_id).to_bytes()
    }
}

impl GmpRequest for GetCredentialRequest {
    type Response = GetCredentialsResponse;
}

/// Semantic request for creating a credential.
#[derive(Debug, Clone)]
pub struct CreateCredentialRequest {
    name: String,
    opts: CredentialOpts,
}

impl CreateCredentialRequest {
    /// Create a credential creation request.
    #[must_use]
    pub fn new(name: impl Into<String>, opts: CredentialOpts) -> Self {
        Self {
            name: name.into(),
            opts,
        }
    }
}

impl Request for CreateCredentialRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_credential(&self.name, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for CreateCredentialRequest {
    type Response = CreateCredentialResponse;
}

/// Semantic request for cloning a credential.
#[derive(Debug, Clone)]
pub struct CloneCredentialRequest {
    credential_id: EntityId,
}

impl CloneCredentialRequest {
    /// Create a credential clone request.
    #[must_use]
    pub fn new(credential_id: EntityId) -> Self {
        Self { credential_id }
    }
}

impl Request for CloneCredentialRequest {
    fn to_bytes(&self) -> Vec<u8> {
        clone_credential(&self.credential_id).to_bytes()
    }
}

impl GmpRequest for CloneCredentialRequest {
    type Response = CreateCredentialResponse;
}

/// Semantic request for modifying a credential.
#[derive(Debug, Clone)]
pub struct ModifyCredentialRequest {
    credential_id: EntityId,
    opts: ModifyCredentialOpts,
}

impl ModifyCredentialRequest {
    /// Create a credential modification request.
    #[must_use]
    pub fn new(credential_id: EntityId, opts: impl Into<ModifyCredentialOpts>) -> Self {
        Self {
            credential_id,
            opts: opts.into(),
        }
    }
}

impl Request for ModifyCredentialRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_credential(&self.credential_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyCredentialRequest {
    type Response = ModifyCredentialResponse;
}

/// Semantic request for deleting a credential.
#[derive(Debug, Clone)]
pub struct DeleteCredentialRequest {
    credential_id: EntityId,
    ultimate: bool,
}

impl DeleteCredentialRequest {
    /// Create a credential deletion request.
    #[must_use]
    pub fn new(credential_id: EntityId, ultimate: bool) -> Self {
        Self {
            credential_id,
            ultimate,
        }
    }
}

impl Request for DeleteCredentialRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_credential(&self.credential_id, self.ultimate).to_bytes()
    }
}

impl GmpRequest for DeleteCredentialRequest {
    type Response = DeleteCredentialResponse;
}

/// Options for `get_credential_stores` requests.
#[derive(Debug, Clone, Default)]
pub struct GetCredentialStoresOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// A credential-store preference update.
#[derive(Debug, Clone, Default)]
pub struct CredentialStorePreference {
    /// Preference name.
    pub name: String,
    /// Preference value.
    pub value: String,
}

/// Optional fields for `modify_credential_store` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyCredentialStoreOpts {
    /// Whether the credential store is active.
    pub active: Option<bool>,
    /// Credential-store host.
    pub host: Option<String>,
    /// Credential-store path.
    pub path: Option<String>,
    /// Credential-store port.
    pub port: Option<u16>,
    /// Optional comment text.
    pub comment: Option<String>,
    /// Preference values to update.
    pub preferences: Vec<CredentialStorePreference>,
}

/// Optional fields for `modify_credential_store_credential` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyCredentialStoreCredentialOpts {
    /// Optional credential name.
    pub name: Option<String>,
    /// Optional comment text.
    pub comment: Option<String>,
    /// Optional credential store identifier.
    pub credential_store_id: Option<EntityId>,
    /// Optional vault identifier.
    pub vault_id: Option<String>,
    /// Optional host identifier.
    pub host_identifier: Option<String>,
}

/// Semantic request for listing or filtering credential stores.
#[derive(Debug, Clone, Default)]
pub struct GetCredentialStoresRequest {
    opts: GetCredentialStoresOpts,
}

impl GetCredentialStoresRequest {
    /// Create a credential-store list request.
    #[must_use]
    pub fn new(opts: GetCredentialStoresOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetCredentialStoresRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_credential_stores_with_opts(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetCredentialStoresRequest {
    type Response = GetCredentialStoresResponse;
}

/// Semantic request for one credential store.
#[derive(Debug, Clone)]
pub struct GetCredentialStoreRequest {
    credential_store_id: EntityId,
    details: Option<bool>,
}

impl GetCredentialStoreRequest {
    /// Create a single credential-store request.
    #[must_use]
    pub fn new(credential_store_id: EntityId, details: Option<bool>) -> Self {
        Self {
            credential_store_id,
            details,
        }
    }
}

impl Request for GetCredentialStoreRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_credential_store(&self.credential_store_id, self.details).to_bytes()
    }
}

impl GmpRequest for GetCredentialStoreRequest {
    type Response = GetCredentialStoresResponse;
}

/// Semantic request for verifying a credential store.
#[derive(Debug, Clone)]
pub struct VerifyCredentialStoreRequest {
    credential_store_id: EntityId,
}

impl VerifyCredentialStoreRequest {
    /// Create a credential-store verification request.
    #[must_use]
    pub fn new(credential_store_id: EntityId) -> Self {
        Self {
            credential_store_id,
        }
    }
}

impl Request for VerifyCredentialStoreRequest {
    fn to_bytes(&self) -> Vec<u8> {
        verify_credential_store(&self.credential_store_id).to_bytes()
    }
}

impl GmpRequest for VerifyCredentialStoreRequest {
    type Response = VerifyCredentialStoreResponse;
}

/// Semantic request for modifying a credential store.
///
/// This type intentionally omits `Debug`: preference values can contain
/// secrets and must not gain a new formatting path through typed execution.
#[derive(Clone)]
pub struct ModifyCredentialStoreRequest {
    credential_store_id: EntityId,
    opts: ModifyCredentialStoreOpts,
}

impl ModifyCredentialStoreRequest {
    /// Create a credential-store modification request.
    #[must_use]
    pub fn new(credential_store_id: EntityId, opts: ModifyCredentialStoreOpts) -> Self {
        Self {
            credential_store_id,
            opts,
        }
    }
}

impl Request for ModifyCredentialStoreRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_credential_store(&self.credential_store_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyCredentialStoreRequest {
    type Response = ModifyCredentialStoreResponse;
}

/// Semantic request for creating a credential-store-backed credential.
#[derive(Debug, Clone)]
pub struct CreateCredentialStoreCredentialRequest {
    name: String,
    credential_type: CredentialStoreCredentialType,
    vault_id: String,
    host_identifier: String,
    opts: CredentialStoreCredentialOpts,
}

impl CreateCredentialStoreCredentialRequest {
    /// Create a credential-store-backed credential request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        credential_type: CredentialStoreCredentialType,
        vault_id: impl Into<String>,
        host_identifier: impl Into<String>,
        opts: CredentialStoreCredentialOpts,
    ) -> Self {
        Self {
            name: name.into(),
            credential_type,
            vault_id: vault_id.into(),
            host_identifier: host_identifier.into(),
            opts,
        }
    }
}

impl Request for CreateCredentialStoreCredentialRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_credential_store_credential(
            &self.name,
            self.credential_type,
            &self.vault_id,
            &self.host_identifier,
            self.opts.clone(),
        )
        .to_bytes()
    }

    fn semantic_command_name(&self) -> Option<&'static str> {
        Some("create_credential_store_credential")
    }
}

impl GmpRequest for CreateCredentialStoreCredentialRequest {
    type Response = CreateCredentialResponse;
}

/// Semantic request for modifying a credential-store-backed credential.
#[derive(Debug, Clone)]
pub struct ModifyCredentialStoreCredentialRequest {
    credential_id: EntityId,
    opts: ModifyCredentialStoreCredentialOpts,
}

impl ModifyCredentialStoreCredentialRequest {
    /// Create a credential-store-backed credential modification request.
    #[must_use]
    pub fn new(credential_id: EntityId, opts: ModifyCredentialStoreCredentialOpts) -> Self {
        Self {
            credential_id,
            opts,
        }
    }
}

impl Request for ModifyCredentialStoreCredentialRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_credential_store_credential(&self.credential_id, self.opts.clone()).to_bytes()
    }

    fn semantic_command_name(&self) -> Option<&'static str> {
        Some("modify_credential_store_credential")
    }
}

impl GmpRequest for ModifyCredentialStoreCredentialRequest {
    type Response = ModifyCredentialResponse;
}

struct SemanticCommand {
    command: XmlCommand,
    semantic_command_name: &'static str,
}

impl Request for SemanticCommand {
    fn to_bytes(&self) -> Vec<u8> {
        self.command.to_bytes()
    }

    fn semantic_command_name(&self) -> Option<&'static str> {
        Some(self.semantic_command_name)
    }
}

/// Build a clone request for an existing credential.
#[must_use]
pub fn clone_credential(credential_id: &EntityId) -> impl Request {
    XmlCommand::new("create_credential").child_with_text("copy", credential_id.as_str())
}

/// Build a `create_credential` request.
#[must_use]
pub fn create_credential(name: &str, opts: CredentialOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_credential");
    cmd.add_element_with_text("name", name);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(credential_type) = opts.credential_type {
        cmd.add_element_with_text("type", credential_type.as_gmp_str());
    }
    add_credential_values(&mut cmd, CredentialValues::from(&opts));
    cmd
}

/// Build a `create_credential` request for a credential-store-backed credential.
#[must_use]
pub fn create_credential_store_credential(
    name: &str,
    credential_type: CredentialStoreCredentialType,
    vault_id: &str,
    host_identifier: &str,
    opts: CredentialStoreCredentialOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("create_credential");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("type", credential_type.as_gmp_str());
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(credential_store_id) = opts.credential_store_id {
        cmd.add_element_with_text("credential_store_id", credential_store_id.as_str());
    }
    cmd.add_element_with_text("vault_id", vault_id);
    cmd.add_element_with_text("host_identifier", host_identifier);
    cmd
}

/// Build a `get_credentials` request.
#[must_use]
pub fn get_credentials(opts: GetCredentialsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_credentials");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_credential` request.
#[must_use]
pub fn get_credential(credential_id: &EntityId) -> impl Request {
    XmlCommand::new("get_credentials")
        .attribute("credential_id", credential_id.as_str())
        .attribute("details", "1")
}

/// Build a `get_credential_stores` request.
#[must_use]
pub fn get_credential_stores() -> impl Request {
    get_credential_stores_with_opts(GetCredentialStoresOpts::default())
}

/// Build a `get_credential_stores` request with optional filters.
#[must_use]
pub fn get_credential_stores_with_opts(opts: GetCredentialStoresOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_credential_stores");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_credential_stores` request for a single credential store.
#[must_use]
pub fn get_credential_store(credential_store_id: &EntityId, details: Option<bool>) -> impl Request {
    let mut cmd = XmlCommand::new("get_credential_stores");
    cmd.add_element_with_text("credential_store_id", credential_store_id.as_str());
    set_optional_bool_attr(&mut cmd, "details", details);
    cmd
}

/// Build a `verify_credential_store` request.
#[must_use]
pub fn verify_credential_store(credential_store_id: &EntityId) -> impl Request {
    XmlCommand::new("verify_credential_store")
        .attribute("credential_store_id", credential_store_id.as_str())
}

/// Build a `modify_credential_store` request.
#[must_use]
pub fn modify_credential_store(
    credential_store_id: &EntityId,
    opts: ModifyCredentialStoreOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("modify_credential_store")
        .attribute("credential_store_id", credential_store_id.as_str());
    if let Some(active) = opts.active {
        cmd.add_element_with_text("active", bool_str(active));
    }
    add_text_element(&mut cmd, "host", opts.host.as_deref());
    add_text_element(&mut cmd, "path", opts.path.as_deref());
    if let Some(port) = opts.port {
        cmd.add_element_with_text("port", &port.to_string());
    }
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if !opts.preferences.is_empty() {
        let preferences = cmd.add_element("preferences");
        for preference in opts.preferences {
            let preference_element = preferences.add_child("preference");
            preference_element.add_child_with_text("name", &preference.name);
            preference_element.add_child_with_text("value", &preference.value);
        }
    }
    cmd
}

/// Build a `modify_credential` request.
#[must_use]
pub fn modify_credential(
    credential_id: &EntityId,
    opts: impl Into<ModifyCredentialOpts>,
) -> impl Request {
    let opts = opts.into();
    let mut cmd =
        XmlCommand::new("modify_credential").attribute("credential_id", credential_id.as_str());
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    add_credential_values(&mut cmd, CredentialValues::from(&opts));
    cmd
}

/// Build a `modify_credential` request for a credential-store-backed credential.
#[must_use]
pub fn modify_credential_store_credential(
    credential_id: &EntityId,
    opts: ModifyCredentialStoreCredentialOpts,
) -> impl Request {
    let mut cmd =
        XmlCommand::new("modify_credential").attribute("credential_id", credential_id.as_str());
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(credential_store_id) = opts.credential_store_id {
        cmd.add_element_with_text("credential_store_id", credential_store_id.as_str());
    }
    add_text_element(&mut cmd, "vault_id", opts.vault_id.as_deref());
    add_text_element(&mut cmd, "host_identifier", opts.host_identifier.as_deref());
    SemanticCommand {
        command: cmd,
        semantic_command_name: "modify_credential_store_credential",
    }
}

/// Build a `delete_credential` request.
#[must_use]
pub fn delete_credential(credential_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_credential")
        .attribute("credential_id", credential_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

struct CredentialValues<'a> {
    login: Option<&'a str>,
    password: Option<&'a str>,
    private_key: Option<&'a str>,
    key_phrase: Option<&'a str>,
    public_key: Option<&'a str>,
    certificate: Option<&'a str>,
    community: Option<&'a str>,
    auth_algorithm: Option<SnmpAuthAlgorithm>,
    privacy_password: Option<&'a str>,
    privacy_algorithm: Option<SnmpPrivacyAlgorithm>,
    allow_insecure: Option<bool>,
    kdc: Option<&'a str>,
    kdcs: &'a [String],
    realm: Option<&'a str>,
}

impl<'a> From<&'a CredentialOpts> for CredentialValues<'a> {
    fn from(opts: &'a CredentialOpts) -> Self {
        Self {
            login: opts.login.as_deref(),
            password: opts.password.as_deref(),
            private_key: opts.private_key.as_deref(),
            key_phrase: opts.key_phrase.as_deref(),
            public_key: opts.public_key.as_deref(),
            certificate: opts.certificate.as_deref(),
            community: opts.community.as_deref(),
            auth_algorithm: opts.auth_algorithm,
            privacy_password: opts.privacy_password.as_deref(),
            privacy_algorithm: opts.privacy_algorithm,
            allow_insecure: opts.allow_insecure,
            kdc: opts.kdc.as_deref(),
            kdcs: &opts.kdcs,
            realm: opts.realm.as_deref(),
        }
    }
}

impl<'a> From<&'a ModifyCredentialOpts> for CredentialValues<'a> {
    fn from(opts: &'a ModifyCredentialOpts) -> Self {
        Self {
            login: opts.login.as_deref(),
            password: opts.password.as_deref(),
            private_key: opts.private_key.as_deref(),
            key_phrase: opts.key_phrase.as_deref(),
            public_key: opts.public_key.as_deref(),
            certificate: opts.certificate.as_deref(),
            community: opts.community.as_deref(),
            auth_algorithm: opts.auth_algorithm,
            privacy_password: opts.privacy_password.as_deref(),
            privacy_algorithm: opts.privacy_algorithm,
            allow_insecure: opts.allow_insecure,
            kdc: opts.kdc.as_deref(),
            kdcs: &opts.kdcs,
            realm: opts.realm.as_deref(),
        }
    }
}

fn add_credential_values(cmd: &mut XmlCommand, values: CredentialValues<'_>) {
    if let Some(allow_insecure) = values.allow_insecure {
        cmd.add_element_with_text("allow_insecure", bool_str(allow_insecure));
    }
    add_text_element(cmd, "certificate", values.certificate);
    add_text_element(cmd, "kdc", values.kdc);
    if !values.kdcs.is_empty() {
        let kdcs = cmd.add_element("kdcs");
        for kdc in values.kdcs {
            kdcs.add_child_with_text("kdc", kdc);
        }
    }
    if values.private_key.is_some() || values.key_phrase.is_some() || values.public_key.is_some() {
        let key = cmd.add_element("key");
        if let Some(phrase) = values.key_phrase {
            key.add_child_with_text("phrase", phrase);
        }
        if let Some(private_key) = values.private_key {
            key.add_child_with_text("private", private_key);
        }
        if let Some(public_key) = values.public_key {
            key.add_child_with_text("public", public_key);
        }
    }
    add_text_element(cmd, "login", values.login);
    add_text_element(cmd, "password", values.password);
    if let Some(auth_algorithm) = values.auth_algorithm {
        cmd.add_element_with_text("auth_algorithm", auth_algorithm.as_gmp_str());
    }
    add_text_element(cmd, "community", values.community);
    if values.privacy_algorithm.is_some() || values.privacy_password.is_some() {
        let privacy = cmd.add_element("privacy");
        if let Some(privacy_algorithm) = values.privacy_algorithm {
            privacy.add_child_with_text("algorithm", privacy_algorithm.as_gmp_str());
        }
        if let Some(privacy_password) = values.privacy_password {
            privacy.add_child_with_text("password", privacy_password);
        }
    }
    add_text_element(cmd, "realm", values.realm);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    #[allow(deprecated)]
    fn credential_commands_build_xml() {
        let rendered = xml(create_credential(
            "cred",
            CredentialOpts {
                credential_type: Some(CredentialType::UsernamePassword),
                login: Some("user".into()),
                password: Some("pass".into()),
                format: Some(CredentialFormat::Pem),
                ..Default::default()
            },
        ));
        assert!(rendered.contains("<type>up</type>"));
        assert!(rendered.contains("<password>pass</password>"));
        assert!(!rendered.contains("<format>"));
        assert_eq!(
            xml(create_credential_store_credential(
                "stored",
                CredentialStoreCredentialType::UsernamePassword,
                "vault-1",
                "host-1",
                CredentialStoreCredentialOpts {
                    comment: Some("from store".into()),
                    credential_store_id: Some(id("cs1")),
                },
            )),
            "<create_credential><name>stored</name><type>cs_up</type><comment>from store</comment><credential_store_id>cs1</credential_store_id><vault_id>vault-1</vault_id><host_identifier>host-1</host_identifier></create_credential>"
        );
        assert_eq!(
            xml(clone_credential(&id("c1"))),
            "<create_credential><copy>c1</copy></create_credential>"
        );
        let rendered = xml(get_credential(&id("c1")));
        assert!(rendered.contains("<get_credentials "));
        assert!(rendered.contains("credential_id=\"c1\""));
        assert!(rendered.contains("details=\"1\""));
        assert_eq!(xml(get_credential_stores()), "<get_credential_stores/>");
        assert_eq!(
            xml(verify_credential_store(&id("cs1"))),
            "<verify_credential_store credential_store_id=\"cs1\"/>"
        );
        assert_eq!(
            xml(get_credential_store(&id("cs1"), Some(true))),
            "<get_credential_stores details=\"1\"><credential_store_id>cs1</credential_store_id></get_credential_stores>"
        );
        assert_eq!(
            xml(get_credential_store(&id("cs1"), Some(false))),
            "<get_credential_stores details=\"0\"><credential_store_id>cs1</credential_store_id></get_credential_stores>"
        );
        assert_eq!(
            xml(get_credential_stores_with_opts(GetCredentialStoresOpts {
                filter_string: Some("name=store".into()),
                filter_id: Some(id("f1")),
                details: Some(true),
            })),
            "<get_credential_stores details=\"1\" filt_id=\"f1\" filter=\"name=store\"/>"
        );
        assert_eq!(
            xml(modify_credential_store(
                &id("cs1"),
                ModifyCredentialStoreOpts {
                    active: Some(true),
                    host: Some("store.example".into()),
                    path: Some("/vault".into()),
                    port: Some(8200),
                    comment: Some("primary".into()),
                    preferences: vec![CredentialStorePreference {
                        name: "token".into(),
                        value: "secret".into(),
                    }],
                },
            )),
            "<modify_credential_store credential_store_id=\"cs1\"><active>1</active><host>store.example</host><path>/vault</path><port>8200</port><comment>primary</comment><preferences><preference><name>token</name><value>secret</value></preference></preferences></modify_credential_store>"
        );
    }

    #[test]
    fn credential_get_modify_delete_build_xml() {
        let rendered = xml(get_credentials(GetCredentialsOpts {
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_credential(
            &id("c1"),
            ModifyCredentialOpts {
                comment: Some("updated".into()),
                ..Default::default()
            },
        ));
        assert_eq!(rendered, "<modify_credential credential_id=\"c1\"><comment>updated</comment></modify_credential>");
        assert_eq!(
            xml(modify_credential_store_credential(
                &id("c1"),
                ModifyCredentialStoreCredentialOpts::default(),
            )),
            "<modify_credential credential_id=\"c1\"/>"
        );
        assert_eq!(
            xml(modify_credential_store_credential(
                &id("c1"),
                ModifyCredentialStoreCredentialOpts {
                    name: Some("store credential".into()),
                    comment: Some("from store".into()),
                    credential_store_id: Some(id("cs1")),
                    vault_id: Some("vault-1".into()),
                    host_identifier: Some("host-1".into()),
                },
            )),
            "<modify_credential credential_id=\"c1\"><name>store credential</name><comment>from store</comment><credential_store_id>cs1</credential_store_id><vault_id>vault-1</vault_id><host_identifier>host-1</host_identifier></modify_credential>"
        );
        assert_eq!(
            xml(delete_credential(&id("c1"), true)),
            "<delete_credential credential_id=\"c1\" ultimate=\"1\"/>"
        );
    }

    #[test]
    fn semantic_credential_requests_match_existing_builders() {
        let credential_id = id("c1");
        let get_opts = GetCredentialsOpts {
            filter_string: Some("name=credential".into()),
            filter_id: Some(id("filter-1")),
            trash: Some(false),
            details: Some(true),
        };
        let create_opts = CredentialOpts {
            comment: Some("created through typed execution".into()),
            credential_type: Some(CredentialType::UsernamePassword),
            login: Some("alice".into()),
            password: Some("create-secret".into()),
            allow_insecure: Some(false),
            ..Default::default()
        };
        let modify_opts = ModifyCredentialOpts {
            name: Some("renamed".into()),
            comment: Some("updated through typed execution".into()),
            login: Some("bob".into()),
            password: Some("modify-secret".into()),
            ..Default::default()
        };

        assert_eq!(
            GetCredentialsRequest::new(get_opts.clone()).to_bytes(),
            get_credentials(get_opts).to_bytes()
        );
        assert_eq!(
            GetCredentialRequest::new(credential_id.clone()).to_bytes(),
            get_credential(&credential_id).to_bytes()
        );
        assert_eq!(
            CreateCredentialRequest::new("credential", create_opts.clone()).to_bytes(),
            create_credential("credential", create_opts).to_bytes()
        );
        assert_eq!(
            CloneCredentialRequest::new(credential_id.clone()).to_bytes(),
            clone_credential(&credential_id).to_bytes()
        );
        assert_eq!(
            ModifyCredentialRequest::new(credential_id.clone(), modify_opts.clone()).to_bytes(),
            modify_credential(&credential_id, modify_opts).to_bytes()
        );
        assert_eq!(
            DeleteCredentialRequest::new(credential_id.clone(), true).to_bytes(),
            delete_credential(&credential_id, true).to_bytes()
        );
    }

    #[test]
    fn semantic_credential_requests_have_the_expected_response_associations() {
        fn assert_response<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: crate::GmpResponse,
        {
        }

        let credential_id = id("credential-1");
        assert_response::<_, GetCredentialsResponse>(&GetCredentialsRequest::default());
        assert_response::<_, GetCredentialsResponse>(&GetCredentialRequest::new(
            credential_id.clone(),
        ));
        assert_response::<_, CreateCredentialResponse>(&CreateCredentialRequest::new(
            "credential",
            CredentialOpts::default(),
        ));
        assert_response::<_, CreateCredentialResponse>(&CloneCredentialRequest::new(
            credential_id.clone(),
        ));
        assert_response::<_, ModifyCredentialResponse>(&ModifyCredentialRequest::new(
            credential_id.clone(),
            ModifyCredentialOpts::default(),
        ));
        assert_response::<_, DeleteCredentialResponse>(&DeleteCredentialRequest::new(
            credential_id,
            false,
        ));
    }

    #[test]
    fn semantic_credential_store_requests_match_existing_builders_and_aliases() {
        let store_id = id("store-1");
        let credential_id = id("credential-1");
        let get_opts = GetCredentialStoresOpts {
            filter_string: Some("name=store".into()),
            filter_id: Some(id("filter-1")),
            details: Some(true),
        };
        let modify_store_opts = ModifyCredentialStoreOpts {
            active: Some(true),
            host: Some("store.example".into()),
            path: Some("/vault".into()),
            port: Some(8200),
            comment: Some("primary".into()),
            preferences: vec![CredentialStorePreference {
                name: "token".into(),
                value: "secret".into(),
            }],
        };
        let create_opts = CredentialStoreCredentialOpts {
            comment: Some("stored credential".into()),
            credential_store_id: Some(store_id.clone()),
        };
        let modify_credential_opts = ModifyCredentialStoreCredentialOpts {
            name: Some("renamed".into()),
            comment: Some("stored credential".into()),
            credential_store_id: Some(store_id.clone()),
            vault_id: Some("vault-2".into()),
            host_identifier: Some("host-2".into()),
        };

        assert_eq!(
            GetCredentialStoresRequest::default().to_bytes(),
            get_credential_stores().to_bytes()
        );
        assert_eq!(
            GetCredentialStoresRequest::new(get_opts.clone()).to_bytes(),
            get_credential_stores_with_opts(get_opts).to_bytes()
        );
        assert_eq!(
            GetCredentialStoreRequest::new(store_id.clone(), Some(true)).to_bytes(),
            get_credential_store(&store_id, Some(true)).to_bytes()
        );
        assert_eq!(
            VerifyCredentialStoreRequest::new(store_id.clone()).to_bytes(),
            verify_credential_store(&store_id).to_bytes()
        );
        assert_eq!(
            ModifyCredentialStoreRequest::new(store_id.clone(), modify_store_opts.clone())
                .to_bytes(),
            modify_credential_store(&store_id, modify_store_opts).to_bytes()
        );

        let create = CreateCredentialStoreCredentialRequest::new(
            "credential",
            CredentialStoreCredentialType::UsernamePassword,
            "vault-1",
            "host-1",
            create_opts.clone(),
        );
        assert_eq!(
            create.to_bytes(),
            create_credential_store_credential(
                "credential",
                CredentialStoreCredentialType::UsernamePassword,
                "vault-1",
                "host-1",
                create_opts,
            )
            .to_bytes()
        );
        assert_eq!(
            create.semantic_command_name(),
            Some("create_credential_store_credential")
        );

        let modify = ModifyCredentialStoreCredentialRequest::new(
            credential_id.clone(),
            modify_credential_opts.clone(),
        );
        assert_eq!(
            modify.to_bytes(),
            modify_credential_store_credential(&credential_id, modify_credential_opts).to_bytes()
        );
        assert_eq!(
            modify.semantic_command_name(),
            Some("modify_credential_store_credential")
        );
    }

    #[test]
    fn semantic_credential_store_requests_have_expected_response_associations() {
        fn assert_response<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: crate::GmpResponse,
        {
        }

        let store_id = id("store-1");
        let credential_id = id("credential-1");
        assert_response::<_, GetCredentialStoresResponse>(&GetCredentialStoresRequest::default());
        assert_response::<_, GetCredentialStoresResponse>(&GetCredentialStoreRequest::new(
            store_id.clone(),
            Some(true),
        ));
        assert_response::<_, VerifyCredentialStoreResponse>(&VerifyCredentialStoreRequest::new(
            store_id.clone(),
        ));
        assert_response::<_, ModifyCredentialStoreResponse>(&ModifyCredentialStoreRequest::new(
            store_id,
            ModifyCredentialStoreOpts::default(),
        ));
        assert_response::<_, CreateCredentialResponse>(
            &CreateCredentialStoreCredentialRequest::new(
                "credential",
                CredentialStoreCredentialType::UsernamePassword,
                "vault-1",
                "host-1",
                CredentialStoreCredentialOpts::default(),
            ),
        );
        assert_response::<_, ModifyCredentialResponse>(
            &ModifyCredentialStoreCredentialRequest::new(
                credential_id,
                ModifyCredentialStoreCredentialOpts::default(),
            ),
        );
    }

    #[test]
    fn credential_value_variants_match_current_gvmd_shape() {
        assert_eq!(
            xml(create_credential(
                "username-password",
                CredentialOpts {
                    credential_type: Some(CredentialType::UsernamePassword),
                    login: Some("user".into()),
                    password: Some("password".into()),
                    ..Default::default()
                }
            )),
            "<create_credential><name>username-password</name><type>up</type><login>user</login><password>password</password></create_credential>"
        );
        assert_eq!(
            xml(create_credential(
                "password-only",
                CredentialOpts {
                    credential_type: Some(CredentialType::PasswordOnly),
                    password: Some("password".into()),
                    ..Default::default()
                }
            )),
            "<create_credential><name>password-only</name><type>pw</type><password>password</password></create_credential>"
        );
        assert_eq!(
            xml(create_credential(
                "ssh",
                CredentialOpts {
                    credential_type: Some(CredentialType::UsernameSshKey),
                    login: Some("root".into()),
                    private_key: Some("PRIVATE".into()),
                    key_phrase: Some("phrase".into()),
                    ..Default::default()
                }
            )),
            "<create_credential><name>ssh</name><type>usk</type><key><phrase>phrase</phrase><private>PRIVATE</private></key><login>root</login></create_credential>"
        );
        assert_eq!(
            xml(create_credential(
                "public",
                CredentialOpts {
                    credential_type: Some(CredentialType::PgpEncryptionKey),
                    public_key: Some("PUBLIC".into()),
                    ..Default::default()
                }
            )),
            "<create_credential><name>public</name><type>pgp</type><key><public>PUBLIC</public></key></create_credential>"
        );
        assert_eq!(
            xml(create_credential(
                "certificate",
                CredentialOpts {
                    credential_type: Some(CredentialType::ClientCertificate),
                    certificate: Some("CERTIFICATE".into()),
                    allow_insecure: Some(true),
                    ..Default::default()
                }
            )),
            "<create_credential><name>certificate</name><type>cc</type><allow_insecure>1</allow_insecure><certificate>CERTIFICATE</certificate></create_credential>"
        );
        assert_eq!(
            xml(create_credential(
                "community",
                CredentialOpts {
                    credential_type: Some(CredentialType::SnmpV1Or2c),
                    community: Some("public".into()),
                    ..Default::default()
                }
            )),
            "<create_credential><name>community</name><type>snmp</type><community>public</community></create_credential>"
        );
        assert_eq!(
            xml(create_credential(
                "snmpv3",
                CredentialOpts {
                    credential_type: Some(CredentialType::SnmpV3),
                    login: Some("snmp-user".into()),
                    password: Some("auth-secret".into()),
                    auth_algorithm: Some(SnmpAuthAlgorithm::Sha1),
                    privacy_password: Some("privacy-secret".into()),
                    privacy_algorithm: Some(SnmpPrivacyAlgorithm::Aes),
                    ..Default::default()
                }
            )),
            "<create_credential><name>snmpv3</name><type>snmp</type><login>snmp-user</login><password>auth-secret</password><auth_algorithm>sha1</auth_algorithm><privacy><algorithm>aes</algorithm><password>privacy-secret</password></privacy></create_credential>"
        );
        assert_eq!(
            xml(create_credential(
                "kerberos",
                CredentialOpts {
                    credential_type: Some(CredentialType::Kerberos5),
                    login: Some("principal".into()),
                    password: Some("secret".into()),
                    kdc: Some("legacy.example".into()),
                    kdcs: vec!["kdc1.example".into(), "kdc2.example".into()],
                    realm: Some("EXAMPLE.COM".into()),
                    ..Default::default()
                }
            )),
            "<create_credential><name>kerberos</name><type>krb5</type><kdc>legacy.example</kdc><kdcs><kdc>kdc1.example</kdc><kdc>kdc2.example</kdc></kdcs><login>principal</login><password>secret</password><realm>EXAMPLE.COM</realm></create_credential>"
        );
    }

    #[test]
    fn modify_credential_supports_name_and_nested_secret_updates() {
        assert_eq!(
            xml(modify_credential(
                &id("c1"),
                ModifyCredentialOpts {
                    name: Some("renamed".into()),
                    private_key: Some("PRIVATE".into()),
                    key_phrase: Some("phrase".into()),
                    privacy_password: Some("privacy-secret".into()),
                    privacy_algorithm: Some(SnmpPrivacyAlgorithm::Des),
                    kdcs: vec!["kdc.example".into()],
                    realm: Some("EXAMPLE.COM".into()),
                    ..Default::default()
                }
            )),
            "<modify_credential credential_id=\"c1\"><name>renamed</name><kdcs><kdc>kdc.example</kdc></kdcs><key><phrase>phrase</phrase><private>PRIVATE</private></key><privacy><algorithm>des</algorithm><password>privacy-secret</password></privacy><realm>EXAMPLE.COM</realm></modify_credential>"
        );
    }

    #[test]
    #[allow(deprecated)]
    fn modify_credential_accepts_legacy_create_options() {
        let opts = CredentialOpts {
            comment: Some("legacy".into()),
            login: Some("alice".into()),
            password: Some("secret".into()),
            credential_type: Some(CredentialType::UsernamePassword),
            format: Some(CredentialFormat::Pem),
            ..Default::default()
        };
        let rendered = xml(modify_credential(&id("c1"), opts.clone()));

        assert_eq!(
            rendered,
            "<modify_credential credential_id=\"c1\"><comment>legacy</comment><login>alice</login><password>secret</password></modify_credential>"
        );
        assert_eq!(
            ModifyCredentialRequest::new(id("c1"), opts).to_bytes(),
            rendered.into_bytes()
        );
    }

    #[test]
    fn credential_debug_output_redacts_secret_values() {
        let opts = CredentialOpts {
            password: Some("password-secret".into()),
            private_key: Some("private-secret".into()),
            key_phrase: Some("phrase-secret".into()),
            community: Some("community-secret".into()),
            privacy_password: Some("privacy-secret".into()),
            ..Default::default()
        };
        let request = CreateCredentialRequest::new("credential", opts.clone());
        let modify_request = ModifyCredentialRequest::new(
            id("c1"),
            ModifyCredentialOpts {
                password: Some("modify-password-secret".into()),
                private_key: Some("modify-private-secret".into()),
                key_phrase: Some("modify-phrase-secret".into()),
                community: Some("modify-community-secret".into()),
                privacy_password: Some("modify-privacy-secret".into()),
                ..Default::default()
            },
        );
        let debug = format!("{opts:?} {request:?} {modify_request:?}");

        for secret in [
            "password-secret",
            "private-secret",
            "phrase-secret",
            "community-secret",
            "privacy-secret",
            "modify-password-secret",
            "modify-private-secret",
            "modify-phrase-secret",
            "modify-community-secret",
            "modify-privacy-secret",
        ] {
            assert!(!debug.contains(secret));
        }
    }
}
