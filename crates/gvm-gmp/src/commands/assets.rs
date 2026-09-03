// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Generic GMP asset command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::responses::{
    CreateAssetResponse, DeleteAssetResponse, GetAssetsResponse, ModifyAssetResponse,
};
use crate::types::EntityId;
use crate::GmpRequest;

/// Typed GMP asset type values.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AssetType {
    /// Host assets.
    Host,
    /// Operating-system assets.
    OperatingSystem,
    /// Forward-compatible custom asset type.
    ///
    /// Current gvmd accepts only `host` for direct creation and `host` or
    /// `os` for retrieval, so custom values may be rejected by the server.
    Custom(String),
}

impl AssetType {
    /// Build a custom/unknown asset type value.
    #[must_use]
    pub fn custom(value: impl Into<String>) -> Self {
        Self::Custom(value.into())
    }

    /// Returns the GMP wire-format string for this value.
    #[must_use]
    pub fn as_gmp_str(&self) -> &str {
        match self {
            Self::Host => "host",
            Self::OperatingSystem => "os",
            Self::Custom(value) => value.as_str(),
        }
    }
}

/// Optional fields for `create_asset` requests.
#[derive(Debug, Clone)]
pub struct CreateAssetOpts {
    /// Asset type to create. Current gvmd accepts only [`AssetType::Host`]
    /// for direct asset creation.
    pub asset_type: AssetType,
    /// Comment text included in the request.
    ///
    /// Current gvmd requires this element for `modify_asset`, so `None` is
    /// serialized as an empty comment and clears any existing value.
    pub comment: Option<String>,
    /// Host name accepted by gvmd, which must be an IPv4 or IPv6 address.
    ///
    /// The field name is retained for source compatibility with the original
    /// generic asset API. It is serialized as the nested GMP `asset/name`
    /// element, not as a `value` element.
    pub value: Option<String>,
}

impl CreateAssetOpts {
    /// Create options for a host asset with the given IP address.
    #[must_use]
    pub fn host(name: impl Into<String>) -> Self {
        Self {
            asset_type: AssetType::Host,
            comment: None,
            value: Some(name.into()),
        }
    }
}

/// Options for `get_assets` requests.
#[derive(Debug, Clone, Default)]
pub struct GetAssetsOpts {
    /// Optional asset identifier.
    pub asset_id: Option<EntityId>,
    /// Compatibility alias for the canonical GMP `type` attribute.
    ///
    /// When both this field and [`Self::type_`] are set, `type_` takes
    /// precedence. The non-standard `asset_type` attribute is never emitted.
    pub asset_type: Option<AssetType>,
    /// Optional `type` attribute.
    pub type_: Option<AssetType>,
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Optional fields for `modify_asset` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyAssetOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Compatibility field retained from the original generic API.
    ///
    /// Current gvmd does not support modifying an asset value, so this field
    /// is deliberately not serialized.
    pub value: Option<String>,
}

/// Optional fields for `delete_asset` requests.
#[derive(Debug, Clone, Default)]
pub struct DeleteAssetOpts {
    /// Compatibility field retained from the original generic API.
    ///
    /// Current gvmd does not accept an `ultimate` attribute for assets and
    /// always applies its asset-specific deletion semantics, so this field is
    /// deliberately not serialized.
    pub ultimate: Option<bool>,
}

/// Semantic request for listing generic assets.
#[derive(Debug, Clone)]
pub struct GetAssetsRequest {
    opts: GetAssetsOpts,
}

impl GetAssetsRequest {
    /// Create a generic asset-list request.
    #[must_use]
    pub fn new(opts: GetAssetsOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetAssetsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_assets(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetAssetsRequest {
    type Response = GetAssetsResponse;
}

/// Semantic request for retrieving one generic asset.
#[derive(Debug, Clone)]
pub struct GetAssetRequest {
    asset_id: EntityId,
    asset_type: AssetType,
}

impl GetAssetRequest {
    /// Create a single-asset request.
    #[must_use]
    pub fn new(asset_id: EntityId, asset_type: AssetType) -> Self {
        Self {
            asset_id,
            asset_type,
        }
    }
}

impl Request for GetAssetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_assets(GetAssetsOpts {
            asset_id: Some(self.asset_id.clone()),
            type_: Some(self.asset_type.clone()),
            details: Some(true),
            ..Default::default()
        })
        .to_bytes()
    }
}

impl GmpRequest for GetAssetRequest {
    type Response = GetAssetsResponse;
}

/// Semantic request for creating a generic asset.
#[derive(Debug, Clone)]
pub struct CreateAssetRequest {
    opts: CreateAssetOpts,
}

impl CreateAssetRequest {
    /// Create a generic asset-creation request.
    #[must_use]
    pub fn new(opts: CreateAssetOpts) -> Self {
        Self { opts }
    }
}

impl Request for CreateAssetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_asset(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for CreateAssetRequest {
    type Response = CreateAssetResponse;
}

/// Semantic request for modifying a generic asset.
#[derive(Debug, Clone)]
pub struct ModifyAssetRequest {
    asset_id: EntityId,
    opts: ModifyAssetOpts,
}

impl ModifyAssetRequest {
    /// Create a generic asset-modification request.
    #[must_use]
    pub fn new(asset_id: EntityId, opts: ModifyAssetOpts) -> Self {
        Self { asset_id, opts }
    }
}

impl Request for ModifyAssetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_asset(&self.asset_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyAssetRequest {
    type Response = ModifyAssetResponse;
}

/// Semantic request for deleting a generic asset.
#[derive(Debug, Clone)]
pub struct DeleteAssetRequest {
    asset_id: EntityId,
    opts: DeleteAssetOpts,
}

impl DeleteAssetRequest {
    /// Create a generic asset-deletion request.
    #[must_use]
    pub fn new(asset_id: EntityId, opts: DeleteAssetOpts) -> Self {
        Self { asset_id, opts }
    }
}

impl Request for DeleteAssetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_asset(&self.asset_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for DeleteAssetRequest {
    type Response = DeleteAssetResponse;
}

/// Build a generic `create_asset` request.
#[must_use]
pub fn create_asset(opts: CreateAssetOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_asset");
    let asset = cmd.add_element("asset");
    asset.add_child_with_text("type", opts.asset_type.as_gmp_str());
    asset.add_child_with_text("name", opts.value.as_deref().unwrap_or_default());
    if let Some(comment) = opts.comment.as_deref().filter(|value| !value.is_empty()) {
        asset.add_child_with_text("comment", comment);
    }
    cmd
}

/// Build a generic `get_assets` request.
#[must_use]
pub fn get_assets(opts: GetAssetsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_assets");
    if let Some(asset_id) = opts.asset_id.as_ref() {
        cmd.set_attribute("asset_id", asset_id.as_str());
    }
    if let Some(type_) = opts.type_.as_ref().or(opts.asset_type.as_ref()) {
        cmd.set_attribute("type", type_.as_gmp_str());
    }
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a generic `modify_asset` request.
#[must_use]
pub fn modify_asset(asset_id: &EntityId, opts: ModifyAssetOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_asset").attribute("asset_id", asset_id.as_str());
    cmd.add_element_with_text("comment", opts.comment.as_deref().unwrap_or_default());
    cmd
}

/// Build a generic `delete_asset` request.
#[must_use]
pub fn delete_asset(asset_id: &EntityId, _opts: DeleteAssetOpts) -> impl Request {
    XmlCommand::new("delete_asset").attribute("asset_id", asset_id.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn asset_type_maps_to_wire_values() {
        assert_eq!(AssetType::Host.as_gmp_str(), "host");
        assert_eq!(AssetType::OperatingSystem.as_gmp_str(), "os");
        assert_eq!(AssetType::custom("firmware").as_gmp_str(), "firmware");
    }

    #[test]
    fn create_asset_builds_xml() {
        assert_eq!(
            xml(create_asset(CreateAssetOpts {
                asset_type: AssetType::Host,
                comment: Some("c".into()),
                value: Some("1.1.1.1".into()),
            })),
            "<create_asset><asset><type>host</type><name>1.1.1.1</name><comment>c</comment></asset></create_asset>"
        );
    }

    #[test]
    fn create_asset_skips_empty_optional_text() {
        assert_eq!(
            xml(create_asset(CreateAssetOpts {
                asset_type: AssetType::Host,
                comment: Some(String::new()),
                value: Some(String::new()),
            })),
            "<create_asset><asset><type>host</type><name></name></asset></create_asset>"
        );
    }

    #[test]
    fn get_assets_builds_xml() {
        assert_eq!(
            xml(get_assets(GetAssetsOpts {
                asset_id: Some(id("a1")),
                asset_type: Some(AssetType::Host),
                type_: Some(AssetType::custom("firmware")),
                filter_string: Some("name=foo".into()),
                filter_id: Some(id("f1")),
                trash: Some(true),
                details: Some(false),
            })),
            "<get_assets asset_id=\"a1\" details=\"0\" filt_id=\"f1\" filter=\"name=foo\" trash=\"1\" type=\"firmware\"/>"
        );
    }

    #[test]
    fn modify_delete_asset_build_xml() {
        assert_eq!(
            xml(modify_asset(
                &id("a1"),
                ModifyAssetOpts {
                    comment: Some("updated".into()),
                    value: Some("v".into()),
                },
            )),
            "<modify_asset asset_id=\"a1\"><comment>updated</comment></modify_asset>"
        );
        assert_eq!(
            xml(modify_asset(
                &id("a1"),
                ModifyAssetOpts {
                    comment: Some(String::new()),
                    value: Some(String::new()),
                },
            )),
            "<modify_asset asset_id=\"a1\"><comment></comment></modify_asset>"
        );
        assert_eq!(
            xml(delete_asset(
                &id("a1"),
                DeleteAssetOpts {
                    ultimate: Some(true),
                },
            )),
            "<delete_asset asset_id=\"a1\"/>"
        );
        assert_eq!(
            xml(delete_asset(&id("a1"), DeleteAssetOpts::default())),
            "<delete_asset asset_id=\"a1\"/>"
        );
    }

    #[test]
    fn semantic_asset_requests_match_builder_bytes_and_responses() {
        fn assert_response<R: GmpRequest<Response = T>, T: crate::GmpResponse>(_: &R) {}

        let get_opts = GetAssetsOpts {
            type_: Some(AssetType::custom("firmware")),
            filter_string: Some("name=example".into()),
            details: Some(true),
            ..Default::default()
        };
        let request = GetAssetsRequest::new(get_opts.clone());
        assert_eq!(request.to_bytes(), get_assets(get_opts).to_bytes());
        assert_response::<_, GetAssetsResponse>(&request);

        let request = GetAssetRequest::new(id("asset-1"), AssetType::OperatingSystem);
        assert_eq!(
            request.to_bytes(),
            get_assets(GetAssetsOpts {
                asset_id: Some(id("asset-1")),
                type_: Some(AssetType::OperatingSystem),
                details: Some(true),
                ..Default::default()
            })
            .to_bytes()
        );
        assert_response::<_, GetAssetsResponse>(&request);

        let create_opts = CreateAssetOpts {
            asset_type: AssetType::Host,
            comment: Some("created".into()),
            value: Some("192.0.2.10".into()),
        };
        let request = CreateAssetRequest::new(create_opts.clone());
        assert_eq!(request.to_bytes(), create_asset(create_opts).to_bytes());
        assert_response::<_, CreateAssetResponse>(&request);

        let modify_opts = ModifyAssetOpts {
            comment: Some("updated".into()),
            value: Some("ignored".into()),
        };
        let request = ModifyAssetRequest::new(id("asset-1"), modify_opts.clone());
        assert_eq!(
            request.to_bytes(),
            modify_asset(&id("asset-1"), modify_opts).to_bytes()
        );
        assert_response::<_, ModifyAssetResponse>(&request);

        let delete_opts = DeleteAssetOpts {
            ultimate: Some(true),
        };
        let request = DeleteAssetRequest::new(id("asset-1"), delete_opts.clone());
        assert_eq!(
            request.to_bytes(),
            delete_asset(&id("asset-1"), delete_opts).to_bytes()
        );
        assert_response::<_, DeleteAssetResponse>(&request);
    }
}
