// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::integration_configs::*;

#[test]
fn test_get_integration_configs_variants() {
    assert_eq!(
        xml(get_integration_configs(GetIntegrationConfigsOpts::default())),
        "<get_integration_configs/>"
    );
    assert_eq!(
        xml(get_integration_configs(GetIntegrationConfigsOpts {
            filter_string: Some("name=demo".into()),
            filter_id: Some(id("f1")),
        })),
        "<get_integration_configs filt_id=\"f1\" filter=\"name=demo\"/>"
    );
    assert_eq!(
        xml(get_integration_config(&id("ic1"), Some(false))),
        "<get_integration_configs details=\"0\" integration_config_id=\"ic1\"/>"
    );
}

#[test]
fn test_modify_integration_config_variants() {
    assert_eq!(
        xml(modify_integration_config(&id("ic1"), Default::default())),
        "<modify_integration_config uuid=\"ic1\"/>"
    );
    assert_eq!(
        xml(modify_integration_config(
            &id("ic1"),
            ModifyIntegrationConfigOpts {
                service_url: Some("https://service.example".into()),
                oidc_provider_client_id: Some("client-id".into()),
                ..Default::default()
            },
        )),
        "<modify_integration_config uuid=\"ic1\"><service><url>https://service.example</url></service><oidc><client><id>client-id</id></client></oidc></modify_integration_config>"
    );
}
