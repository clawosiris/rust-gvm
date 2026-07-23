// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Integration configuration command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::types::EntityId;

/// Options for `get_integration_configs` requests.
#[derive(Debug, Clone, Default)]
pub struct GetIntegrationConfigsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
}

/// Options for a full `modify_integration_config` replacement.
///
/// gvmd requires the service URL, OIDC URL, client ID, and client secret
/// together when any configurable value is non-empty. Leaving every field
/// unset clears the integration configuration.
#[derive(Debug, Clone, Default)]
pub struct ModifyIntegrationConfigOpts {
    /// Optional integration service URL.
    pub service_url: Option<String>,
    /// Optional integration service CA certificate.
    pub service_cacert: Option<String>,
    /// Optional OIDC provider URL.
    pub oidc_provider_url: Option<String>,
    /// Optional OIDC provider client id.
    pub oidc_provider_client_id: Option<String>,
    /// Optional OIDC provider client secret.
    pub oidc_provider_client_secret: Option<String>,
}

/// Build a `get_integration_configs` request.
#[must_use]
pub fn get_integration_configs(opts: GetIntegrationConfigsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_integration_configs");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    cmd
}

/// Build a `get_integration_config` request.
#[must_use]
pub fn get_integration_config(
    integration_config_id: &EntityId,
    details: Option<bool>,
) -> impl Request {
    let mut cmd = XmlCommand::new("get_integration_configs")
        .attribute("integration_config_id", integration_config_id.as_str());
    set_optional_bool_attr(&mut cmd, "details", details);
    cmd
}

/// Build a schema-complete `modify_integration_config` request.
#[must_use]
pub fn modify_integration_config(
    integration_config_id: &EntityId,
    opts: ModifyIntegrationConfigOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("modify_integration_config")
        .attribute("uuid", integration_config_id.as_str());

    let service = cmd.add_element("service");
    service.add_child_with_text("url", opts.service_url.as_deref().unwrap_or_default());
    service.add_child_with_text("cacert", opts.service_cacert.as_deref().unwrap_or_default());

    let oidc = cmd.add_element("oidc");
    oidc.add_child_with_text("url", opts.oidc_provider_url.as_deref().unwrap_or_default());

    let client = oidc.add_child("client");
    client.add_child_with_text(
        "id",
        opts.oidc_provider_client_id.as_deref().unwrap_or_default(),
    );
    client.add_child_with_text(
        "secret",
        opts.oidc_provider_client_secret
            .as_deref()
            .unwrap_or_default(),
    );

    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn integration_config_gets_build_xml() {
        assert_eq!(
            xml(get_integration_configs(GetIntegrationConfigsOpts {
                filter_string: Some("name=demo".into()),
                filter_id: Some(id("f1")),
            })),
            "<get_integration_configs filt_id=\"f1\" filter=\"name=demo\"/>"
        );
        assert_eq!(
            xml(get_integration_config(&id("ic1"), Some(true))),
            "<get_integration_configs details=\"1\" integration_config_id=\"ic1\"/>"
        );
    }

    #[test]
    fn integration_config_modify_builds_xml() {
        assert_eq!(
            xml(modify_integration_config(
                &id("ic1"),
                ModifyIntegrationConfigOpts {
                    service_url: Some("https://service.example".into()),
                    service_cacert: Some("CERT".into()),
                    oidc_provider_url: Some("https://oidc.example".into()),
                    oidc_provider_client_id: Some("client-id".into()),
                    oidc_provider_client_secret: Some("client-secret".into()),
                }
            )),
            "<modify_integration_config uuid=\"ic1\"><service><url>https://service.example</url><cacert>CERT</cacert></service><oidc><url>https://oidc.example</url><client><id>client-id</id><secret>client-secret</secret></client></oidc></modify_integration_config>"
        );
        assert_eq!(
            xml(modify_integration_config(&id("ic1"), Default::default())),
            "<modify_integration_config uuid=\"ic1\"><service><url></url><cacert></cacert></service><oidc><url></url><client><id></id><secret></secret></client></oidc></modify_integration_config>"
        );
    }
}
