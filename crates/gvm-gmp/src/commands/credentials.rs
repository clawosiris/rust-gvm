//! Credential command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::{CredentialFormat, CredentialType, SnmpAuthAlgorithm, SnmpPrivacyAlgorithm};
use crate::types::EntityId;

/// Optional fields for credential create and modify requests.
#[derive(Debug, Clone, Default)]
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
    /// Optional certificate data.
    pub certificate: Option<String>,
    /// Optional SNMP authentication algorithm.
    pub auth_algorithm: Option<SnmpAuthAlgorithm>,
    /// Optional SNMP privacy algorithm.
    pub privacy_algorithm: Option<SnmpPrivacyAlgorithm>,
    /// Optional credential or report format value.
    pub format: Option<CredentialFormat>,
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

/// Build a clone request for an existing credential.
pub fn clone_credential(credential_id: &EntityId) -> impl Request {
    XmlCommand::new("create_credential").child_with_text("copy", credential_id.as_str())
}

/// Build a `create_credential` request.
pub fn create_credential(name: &str, opts: CredentialOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_credential");
    cmd.add_element_with_text("name", name);
    add_credential_body(&mut cmd, &opts);
    cmd
}

/// Build a `get_credentials` request.
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
pub fn get_credential(credential_id: &EntityId) -> impl Request {
    XmlCommand::new("get_credentials")
        .attribute("credential_id", credential_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_credential` request.
pub fn modify_credential(credential_id: &EntityId, opts: CredentialOpts) -> impl Request {
    let mut cmd =
        XmlCommand::new("modify_credential").attribute("credential_id", credential_id.as_str());
    add_credential_body(&mut cmd, &opts);
    cmd
}

/// Build a `delete_credential` request.
pub fn delete_credential(credential_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_credential")
        .attribute("credential_id", credential_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_credential_body(cmd: &mut XmlCommand, opts: &CredentialOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    if let Some(credential_type) = opts.credential_type {
        cmd.add_element_with_text("type", credential_type.as_gmp_str());
    }
    add_text_element(cmd, "login", opts.login.as_deref());
    add_text_element(cmd, "password", opts.password.as_deref());
    add_text_element(cmd, "private", opts.private_key.as_deref());
    add_text_element(cmd, "certificate", opts.certificate.as_deref());
    if let Some(auth_algorithm) = opts.auth_algorithm {
        cmd.add_element_with_text("auth_algorithm", auth_algorithm.as_gmp_str());
    }
    if let Some(privacy_algorithm) = opts.privacy_algorithm {
        cmd.add_element_with_text("privacy_algorithm", privacy_algorithm.as_gmp_str());
    }
    if let Some(format) = opts.format {
        cmd.add_element_with_text("format", format.as_gmp_str());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
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
        assert_eq!(
            xml(clone_credential(&id("c1"))),
            "<create_credential><copy>c1</copy></create_credential>"
        );
        let rendered = xml(get_credential(&id("c1")));
        assert!(rendered.contains("<get_credentials "));
        assert!(rendered.contains("credential_id=\"c1\""));
        assert!(rendered.contains("details=\"1\""));
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
            CredentialOpts {
                comment: Some("updated".into()),
                ..Default::default()
            },
        ));
        assert_eq!(rendered, "<modify_credential credential_id=\"c1\"><comment>updated</comment></modify_credential>");
        assert_eq!(
            xml(delete_credential(&id("c1"), true)),
            "<delete_credential credential_id=\"c1\" ultimate=\"1\"/>"
        );
    }
}
