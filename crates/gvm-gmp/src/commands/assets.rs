// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Generic GMP asset command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::types::EntityId;

/// Typed GMP asset type values.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AssetType {
    /// Host assets.
    Host,
    /// Operating-system assets.
    OperatingSystem,
    /// Forward-compatible custom asset type.
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
    /// Asset type to create.
    pub asset_type: AssetType,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional free-form value payload.
    pub value: Option<String>,
}

/// Options for `get_assets` requests.
#[derive(Debug, Clone, Default)]
pub struct GetAssetsOpts {
    /// Optional asset identifier.
    pub asset_id: Option<EntityId>,
    /// Optional `asset_type` attribute.
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
    /// Optional free-form value payload.
    pub value: Option<String>,
}

/// Optional fields for `delete_asset` requests.
#[derive(Debug, Clone, Default)]
pub struct DeleteAssetOpts {
    /// Whether to permanently delete the asset.
    pub ultimate: Option<bool>,
}

/// Build a generic `create_asset` request.
#[must_use]
pub fn create_asset(opts: CreateAssetOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_asset");
    cmd.add_element_with_text("asset_type", opts.asset_type.as_gmp_str());
    add_asset_body(&mut cmd, &opts.comment, &opts.value);
    cmd
}

/// Build a generic `get_assets` request.
#[must_use]
pub fn get_assets(opts: GetAssetsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_assets");
    if let Some(asset_id) = opts.asset_id.as_ref() {
        cmd.set_attribute("asset_id", asset_id.as_str());
    }
    if let Some(asset_type) = opts.asset_type.as_ref() {
        cmd.set_attribute("asset_type", asset_type.as_gmp_str());
    }
    if let Some(asset_type) = opts.type_.as_ref() {
        cmd.set_attribute("type", asset_type.as_gmp_str());
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
    add_asset_body(&mut cmd, &opts.comment, &opts.value);
    cmd
}

/// Build a generic `delete_asset` request.
#[must_use]
pub fn delete_asset(asset_id: &EntityId, opts: DeleteAssetOpts) -> impl Request {
    let mut cmd = XmlCommand::new("delete_asset").attribute("asset_id", asset_id.as_str());
    if let Some(ultimate) = opts.ultimate {
        cmd.set_attribute("ultimate", bool_str(ultimate));
    }
    cmd
}

fn add_asset_body(cmd: &mut XmlCommand, comment: &Option<String>, value: &Option<String>) {
    add_text_element(cmd, "comment", comment.as_deref());
    add_text_element(cmd, "value", value.as_deref());
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
            "<create_asset><asset_type>host</asset_type><comment>c</comment><value>1.1.1.1</value></create_asset>"
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
            "<create_asset><asset_type>host</asset_type></create_asset>"
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
            "<get_assets asset_id=\"a1\" asset_type=\"host\" details=\"0\" filt_id=\"f1\" filter=\"name=foo\" trash=\"1\" type=\"firmware\"/>"
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
            "<modify_asset asset_id=\"a1\"><comment>updated</comment><value>v</value></modify_asset>"
        );
        assert_eq!(
            xml(modify_asset(
                &id("a1"),
                ModifyAssetOpts {
                    comment: Some(String::new()),
                    value: Some(String::new()),
                },
            )),
            "<modify_asset asset_id=\"a1\"/>"
        );
        assert_eq!(
            xml(delete_asset(
                &id("a1"),
                DeleteAssetOpts {
                    ultimate: Some(true),
                },
            )),
            "<delete_asset asset_id=\"a1\" ultimate=\"1\"/>"
        );
        assert_eq!(
            xml(delete_asset(&id("a1"), DeleteAssetOpts::default())),
            "<delete_asset asset_id=\"a1\"/>"
        );
    }
}
