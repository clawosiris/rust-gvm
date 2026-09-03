// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Operating-system asset command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::commands::assets::{
    delete_asset, get_assets, AssetType, DeleteAssetOpts, GetAssetsOpts,
};
use crate::responses::{
    DeleteAssetResponse, GetOperatingSystemAssetsResponse, ModifyAssetResponse,
};
use crate::types::EntityId;
use crate::GmpRequest;

/// Options for `get_operating_systems` requests.
#[derive(Debug, Clone, Default)]
pub struct GetOperatingSystemsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Semantic request for listing operating-system assets.
#[derive(Debug, Clone)]
pub struct GetOperatingSystemAssetsRequest {
    opts: GetOperatingSystemsOpts,
}

impl GetOperatingSystemAssetsRequest {
    /// Create an operating-system asset-list request.
    #[must_use]
    pub fn new(opts: GetOperatingSystemsOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetOperatingSystemAssetsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_operating_systems(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetOperatingSystemAssetsRequest {
    type Response = GetOperatingSystemAssetsResponse;
}

/// Semantic request for retrieving one operating-system asset.
#[derive(Debug, Clone)]
pub struct GetOperatingSystemAssetRequest {
    operating_system_id: EntityId,
    details: Option<bool>,
}

impl GetOperatingSystemAssetRequest {
    /// Create a single operating-system asset request.
    #[must_use]
    pub fn new(operating_system_id: EntityId, details: Option<bool>) -> Self {
        Self {
            operating_system_id,
            details,
        }
    }
}

impl Request for GetOperatingSystemAssetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_operating_system(&self.operating_system_id, self.details).to_bytes()
    }
}

impl GmpRequest for GetOperatingSystemAssetRequest {
    type Response = GetOperatingSystemAssetsResponse;
}

/// Semantic request for modifying an operating-system asset.
#[derive(Debug, Clone)]
pub struct ModifyOperatingSystemAssetRequest {
    operating_system_id: EntityId,
    comment: Option<String>,
}

impl ModifyOperatingSystemAssetRequest {
    /// Create an operating-system asset-modification request.
    #[must_use]
    pub fn new(operating_system_id: EntityId, comment: Option<String>) -> Self {
        Self {
            operating_system_id,
            comment,
        }
    }
}

impl Request for ModifyOperatingSystemAssetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_operating_system(&self.operating_system_id, self.comment.as_deref()).to_bytes()
    }
}

impl GmpRequest for ModifyOperatingSystemAssetRequest {
    type Response = ModifyAssetResponse;
}

/// Semantic request for deleting an operating-system asset.
#[derive(Debug, Clone)]
pub struct DeleteOperatingSystemAssetRequest {
    operating_system_id: EntityId,
}

impl DeleteOperatingSystemAssetRequest {
    /// Create an operating-system asset-deletion request.
    #[must_use]
    pub fn new(operating_system_id: EntityId) -> Self {
        Self {
            operating_system_id,
        }
    }
}

impl Request for DeleteOperatingSystemAssetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_operating_system(&self.operating_system_id).to_bytes()
    }
}

impl GmpRequest for DeleteOperatingSystemAssetRequest {
    type Response = DeleteAssetResponse;
}

/// Build a `get_operating_systems` request.
#[must_use]
pub fn get_operating_systems(opts: GetOperatingSystemsOpts) -> impl Request {
    get_assets(GetAssetsOpts {
        type_: Some(AssetType::OperatingSystem),
        filter_string: opts.filter_string,
        filter_id: opts.filter_id,
        details: opts.details,
        ..Default::default()
    })
}

/// Build a `get_operating_system` request.
#[must_use]
pub fn get_operating_system(operating_system_id: &EntityId, details: Option<bool>) -> impl Request {
    get_assets(GetAssetsOpts {
        asset_id: Some(operating_system_id.clone()),
        type_: Some(AssetType::OperatingSystem),
        details,
        ..Default::default()
    })
}

/// Build a `modify_operating_system` request.
#[must_use]
pub fn modify_operating_system(
    operating_system_id: &EntityId,
    comment: Option<&str>,
) -> impl Request {
    let mut cmd =
        XmlCommand::new("modify_asset").attribute("asset_id", operating_system_id.as_str());
    cmd.add_element_with_text("comment", comment.unwrap_or_default());
    cmd
}

/// Build a `delete_operating_system` request.
#[must_use]
pub fn delete_operating_system(operating_system_id: &EntityId) -> impl Request {
    delete_asset(operating_system_id, DeleteAssetOpts::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn operating_system_gets_build_xml() {
        assert_eq!(
            xml(get_operating_systems(GetOperatingSystemsOpts {
                filter_string: Some("name=Debian".into()),
                filter_id: Some(id("f1")),
                details: Some(true),
            })),
            "<get_assets details=\"1\" filt_id=\"f1\" filter=\"name=Debian\" type=\"os\"/>"
        );
        assert_eq!(
            xml(get_operating_system(&id("os1"), Some(false))),
            "<get_assets asset_id=\"os1\" details=\"0\" type=\"os\"/>"
        );
    }

    #[test]
    fn operating_system_modify_delete_build_xml() {
        assert_eq!(
            xml(modify_operating_system(&id("os1"), Some("updated"))),
            "<modify_asset asset_id=\"os1\"><comment>updated</comment></modify_asset>"
        );
        assert_eq!(
            xml(modify_operating_system(&id("os1"), None)),
            "<modify_asset asset_id=\"os1\"><comment></comment></modify_asset>"
        );
        assert_eq!(
            xml(delete_operating_system(&id("os1"))),
            "<delete_asset asset_id=\"os1\"/>"
        );
    }

    #[test]
    fn semantic_operating_system_asset_requests_match_builder_bytes_and_responses() {
        fn assert_response<R: GmpRequest<Response = T>, T: crate::GmpResponse>(_: &R) {}

        let opts = GetOperatingSystemsOpts {
            filter_string: Some("name=Debian".into()),
            filter_id: Some(id("filter-1")),
            details: Some(true),
        };
        let request = GetOperatingSystemAssetsRequest::new(opts.clone());
        assert_eq!(request.to_bytes(), get_operating_systems(opts).to_bytes());
        assert_response::<_, GetOperatingSystemAssetsResponse>(&request);

        let request = GetOperatingSystemAssetRequest::new(id("os-1"), Some(false));
        assert_eq!(
            request.to_bytes(),
            get_operating_system(&id("os-1"), Some(false)).to_bytes()
        );
        assert_response::<_, GetOperatingSystemAssetsResponse>(&request);

        let request =
            ModifyOperatingSystemAssetRequest::new(id("os-1"), Some("updated".to_string()));
        assert_eq!(
            request.to_bytes(),
            modify_operating_system(&id("os-1"), Some("updated")).to_bytes()
        );
        assert_response::<_, ModifyAssetResponse>(&request);

        let request = DeleteOperatingSystemAssetRequest::new(id("os-1"));
        assert_eq!(
            request.to_bytes(),
            delete_operating_system(&id("os-1")).to_bytes()
        );
        assert_response::<_, DeleteAssetResponse>(&request);
    }
}
