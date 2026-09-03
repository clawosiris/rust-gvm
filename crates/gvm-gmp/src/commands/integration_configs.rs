// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Integration configuration command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::responses::{GetIntegrationConfigsResponse, ModifyIntegrationConfigResponse};
use crate::types::EntityId;
use crate::GmpRequest;

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

/// Semantic request for listing integration configurations.
#[derive(Debug, Clone, Default)]
pub struct GetIntegrationConfigsRequest(GetIntegrationConfigsOpts);

impl GetIntegrationConfigsRequest {
    /// Create an integration-configuration list request.
    #[must_use]
    pub fn new(opts: GetIntegrationConfigsOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetIntegrationConfigsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_integration_configs(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetIntegrationConfigsRequest {
    type Response = GetIntegrationConfigsResponse;
}

/// Semantic request for one integration configuration.
#[derive(Debug, Clone)]
pub struct GetIntegrationConfigRequest {
    integration_config_id: EntityId,
    details: Option<bool>,
}

impl GetIntegrationConfigRequest {
    /// Create a single integration-configuration request.
    #[must_use]
    pub fn new(integration_config_id: EntityId, details: Option<bool>) -> Self {
        Self {
            integration_config_id,
            details,
        }
    }
}

impl Request for GetIntegrationConfigRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_integration_config(&self.integration_config_id, self.details).to_bytes()
    }
}

impl GmpRequest for GetIntegrationConfigRequest {
    type Response = GetIntegrationConfigsResponse;
}

/// Semantic request for modifying an integration configuration.
#[derive(Clone)]
pub struct ModifyIntegrationConfigRequest {
    integration_config_id: EntityId,
    opts: ModifyIntegrationConfigOpts,
}

impl std::fmt::Debug for ModifyIntegrationConfigRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModifyIntegrationConfigRequest")
            .field("integration_config_id", &self.integration_config_id)
            .field("service_url", &self.opts.service_url)
            .field(
                "service_cacert",
                &self.opts.service_cacert.as_ref().map(|_| "<redacted>"),
            )
            .field("oidc_provider_url", &self.opts.oidc_provider_url)
            .field(
                "oidc_provider_client_id",
                &self.opts.oidc_provider_client_id,
            )
            .field(
                "oidc_provider_client_secret",
                &self
                    .opts
                    .oidc_provider_client_secret
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl ModifyIntegrationConfigRequest {
    /// Create an integration-configuration modification request.
    #[must_use]
    pub fn new(integration_config_id: EntityId, opts: ModifyIntegrationConfigOpts) -> Self {
        Self {
            integration_config_id,
            opts,
        }
    }
}

impl Request for ModifyIntegrationConfigRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_integration_config(&self.integration_config_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyIntegrationConfigRequest {
    type Response = ModifyIntegrationConfigResponse;
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
    use crate::responses::{GetIntegrationConfigsResponse, ModifyIntegrationConfigResponse};

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

    #[test]
    fn semantic_requests_preserve_builder_bytes_and_response_associations() {
        fn get<R: GmpRequest<Response = GetIntegrationConfigsResponse>>(_: &R) {}
        fn modify<R: GmpRequest<Response = ModifyIntegrationConfigResponse>>(_: &R) {}

        let config_id = id("ic1");
        let get_opts = GetIntegrationConfigsOpts {
            filter_string: Some("name=demo".into()),
            filter_id: Some(id("f1")),
        };
        let modify_opts = ModifyIntegrationConfigOpts {
            service_url: Some("https://service.example".into()),
            service_cacert: Some("CERT".into()),
            oidc_provider_url: Some("https://oidc.example".into()),
            oidc_provider_client_id: Some("client-id".into()),
            oidc_provider_client_secret: Some("client-secret".into()),
        };

        let list = GetIntegrationConfigsRequest::new(get_opts.clone());
        get(&list);
        assert_eq!(
            list.to_bytes(),
            get_integration_configs(get_opts).to_bytes()
        );
        let single = GetIntegrationConfigRequest::new(config_id.clone(), Some(true));
        get(&single);
        assert_eq!(
            single.to_bytes(),
            get_integration_config(&config_id, Some(true)).to_bytes()
        );
        let modify_request =
            ModifyIntegrationConfigRequest::new(config_id.clone(), modify_opts.clone());
        modify(&modify_request);
        assert_eq!(
            modify_request.to_bytes(),
            modify_integration_config(&config_id, modify_opts).to_bytes()
        );
        let debug = format!("{modify_request:?}");
        assert!(!debug.contains("CERT"));
        assert!(!debug.contains("client-secret"));
        assert!(debug.contains("<redacted>"));
    }
}
