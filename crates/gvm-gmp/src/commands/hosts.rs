// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Host command builders.

use gvm_protocol::Request;

use crate::commands::assets::{
    create_asset, delete_asset, get_assets, modify_asset, AssetType, CreateAssetOpts,
    DeleteAssetOpts, GetAssetsOpts, ModifyAssetOpts,
};
use crate::types::EntityId;

/// Optional fields for host create and modify requests.
#[derive(Debug, Clone, Default)]
pub struct HostOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional free-form value payload.
    pub value: Option<String>,
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
        asset_type: Some(AssetType::Host),
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
        asset_type: Some(AssetType::Host),
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
            value: opts.value,
        },
    )
}

/// Build a `delete_host` request.
#[must_use]
pub fn delete_host(host_id: &EntityId, ultimate: bool) -> impl Request {
    delete_asset(
        host_id,
        DeleteAssetOpts {
            ultimate: Some(ultimate),
        },
    )
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
        assert!(rendered.contains("<asset_type>host</asset_type>"));
        assert!(rendered.contains("<value>1.1.1.1</value>"));
        assert_eq!(
            xml(get_host(&id("h1"))),
            "<get_assets asset_id=\"h1\" asset_type=\"host\" details=\"1\" type=\"host\"/>"
        );
    }

    #[test]
    fn host_get_modify_delete_build_xml() {
        let rendered = xml(get_hosts(GetHostsOpts {
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("asset_type=\"host\""));
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
            "<delete_asset asset_id=\"h1\" ultimate=\"0\"/>"
        );
    }
}
