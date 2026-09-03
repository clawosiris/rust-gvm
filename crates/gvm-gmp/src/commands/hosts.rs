// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Host command builders.

use gvm_protocol::Request;

use crate::commands::assets::{
    create_asset, delete_asset, get_assets, modify_asset, AssetType, CreateAssetOpts,
    DeleteAssetOpts, GetAssetsOpts, ModifyAssetOpts,
};
use crate::responses::{
    CreateHostResponse, DeleteHostResponse, GetHostsResponse, ModifyHostResponse,
};
use crate::types::EntityId;
use crate::GmpRequest;

/// Optional fields for host create and modify requests.
#[derive(Debug, Clone, Default)]
pub struct HostOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Host IPv4 or IPv6 address used as the asset name when creating a host.
    ///
    /// This field is ignored by `modify_host`, because current gvmd only
    /// supports modifying the host comment.
    pub value: Option<String>,
}

impl HostOpts {
    /// Create options for the given host IP address.
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            comment: None,
            value: Some(name.into()),
        }
    }
}

/// Options for `get_hosts` requests.
#[derive(Debug, Clone, Default)]
pub struct GetHostsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Semantic request for listing host assets.
#[derive(Debug, Clone)]
pub struct GetHostsRequest {
    opts: GetHostsOpts,
}

impl GetHostsRequest {
    /// Create a host-list request.
    #[must_use]
    pub fn new(opts: GetHostsOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetHostsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_hosts(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetHostsRequest {
    type Response = GetHostsResponse;
}

/// Semantic request for retrieving one host asset.
#[derive(Debug, Clone)]
pub struct GetHostRequest {
    host_id: EntityId,
}

impl GetHostRequest {
    /// Create a single-host request.
    #[must_use]
    pub fn new(host_id: EntityId) -> Self {
        Self { host_id }
    }
}

impl Request for GetHostRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_host(&self.host_id).to_bytes()
    }
}

impl GmpRequest for GetHostRequest {
    type Response = GetHostsResponse;
}

/// Semantic request for creating a host asset.
#[derive(Debug, Clone)]
pub struct CreateHostRequest {
    opts: HostOpts,
}

impl CreateHostRequest {
    /// Create a host-creation request.
    #[must_use]
    pub fn new(opts: HostOpts) -> Self {
        Self { opts }
    }
}

impl Request for CreateHostRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_host(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for CreateHostRequest {
    type Response = CreateHostResponse;
}

/// Semantic request for modifying a host asset.
#[derive(Debug, Clone)]
pub struct ModifyHostRequest {
    host_id: EntityId,
    opts: HostOpts,
}

impl ModifyHostRequest {
    /// Create a host-modification request.
    #[must_use]
    pub fn new(host_id: EntityId, opts: HostOpts) -> Self {
        Self { host_id, opts }
    }
}

impl Request for ModifyHostRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_host(&self.host_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyHostRequest {
    type Response = ModifyHostResponse;
}

/// Semantic request for deleting a host asset.
#[derive(Debug, Clone)]
pub struct DeleteHostRequest {
    host_id: EntityId,
    ultimate: bool,
}

impl DeleteHostRequest {
    /// Create a host-deletion request.
    #[must_use]
    pub fn new(host_id: EntityId, ultimate: bool) -> Self {
        Self { host_id, ultimate }
    }
}

impl Request for DeleteHostRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_host(&self.host_id, self.ultimate).to_bytes()
    }
}

impl GmpRequest for DeleteHostRequest {
    type Response = DeleteHostResponse;
}

/// Build a `create_host` request.
#[must_use]
pub fn create_host(opts: HostOpts) -> impl Request {
    create_asset(CreateAssetOpts {
        asset_type: AssetType::Host,
        comment: opts.comment,
        value: opts.value,
    })
}

/// Build a `get_hosts` request.
#[must_use]
pub fn get_hosts(opts: GetHostsOpts) -> impl Request {
    get_assets(GetAssetsOpts {
        type_: Some(AssetType::Host),
        filter_string: opts.filter_string,
        filter_id: opts.filter_id,
        trash: opts.trash,
        details: opts.details,
        ..Default::default()
    })
}

/// Build a `get_host` request.
#[must_use]
pub fn get_host(host_id: &EntityId) -> impl Request {
    get_assets(GetAssetsOpts {
        asset_id: Some(host_id.clone()),
        type_: Some(AssetType::Host),
        details: Some(true),
        ..Default::default()
    })
}

/// Build a `modify_host` request.
#[must_use]
pub fn modify_host(host_id: &EntityId, opts: HostOpts) -> impl Request {
    modify_asset(
        host_id,
        ModifyAssetOpts {
            comment: opts.comment,
            value: None,
        },
    )
}

/// Build a `delete_host` request.
///
/// The `ultimate` argument is retained for API compatibility but is ignored:
/// current gvmd does not accept an `ultimate` attribute for asset deletion.
#[must_use]
pub fn delete_host(host_id: &EntityId, _ultimate: bool) -> impl Request {
    delete_asset(host_id, DeleteAssetOpts { ultimate: None })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn host_commands_build_xml() {
        let rendered = xml(create_host(HostOpts {
            value: Some("1.1.1.1".into()),
            ..Default::default()
        }));
        assert!(rendered.contains("<type>host</type>"));
        assert!(rendered.contains("<name>1.1.1.1</name>"));
        assert_eq!(
            xml(get_host(&id("h1"))),
            "<get_assets asset_id=\"h1\" details=\"1\" type=\"host\"/>"
        );
    }

    #[test]
    fn host_get_modify_delete_build_xml() {
        let rendered = xml(get_hosts(GetHostsOpts {
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("type=\"host\""));
        let rendered = xml(modify_host(
            &id("h1"),
            HostOpts {
                comment: Some("updated".into()),
                ..Default::default()
            },
        ));
        assert_eq!(
            rendered,
            "<modify_asset asset_id=\"h1\"><comment>updated</comment></modify_asset>"
        );
        assert_eq!(
            xml(delete_host(&id("h1"), false)),
            "<delete_asset asset_id=\"h1\"/>"
        );
    }

    #[test]
    fn semantic_host_requests_match_builder_bytes_and_responses() {
        fn assert_response<R: GmpRequest<Response = T>, T: crate::GmpResponse>(_: &R) {}

        let get_opts = GetHostsOpts {
            filter_string: Some("name=host".into()),
            details: Some(true),
            ..Default::default()
        };
        let request = GetHostsRequest::new(get_opts.clone());
        assert_eq!(request.to_bytes(), get_hosts(get_opts).to_bytes());
        assert_response::<_, GetHostsResponse>(&request);

        let request = GetHostRequest::new(id("host-1"));
        assert_eq!(request.to_bytes(), get_host(&id("host-1")).to_bytes());
        assert_response::<_, GetHostsResponse>(&request);

        let host_opts = HostOpts {
            comment: Some("host".into()),
            value: Some("192.0.2.10".into()),
        };
        let request = CreateHostRequest::new(host_opts.clone());
        assert_eq!(request.to_bytes(), create_host(host_opts).to_bytes());
        assert_response::<_, CreateHostResponse>(&request);

        let modify_opts = HostOpts {
            comment: Some("updated".into()),
            value: Some("ignored".into()),
        };
        let request = ModifyHostRequest::new(id("host-1"), modify_opts.clone());
        assert_eq!(
            request.to_bytes(),
            modify_host(&id("host-1"), modify_opts).to_bytes()
        );
        assert_response::<_, ModifyHostResponse>(&request);

        let request = DeleteHostRequest::new(id("host-1"), true);
        assert_eq!(
            request.to_bytes(),
            delete_host(&id("host-1"), true).to_bytes()
        );
        assert_response::<_, DeleteHostResponse>(&request);
    }
}
