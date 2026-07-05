// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::configs::*;
use gvm_gmp::commands::scan_configs::{
    clone_policy, clone_scan_config, create_policy, create_scan_config, delete_policy,
    delete_scan_config, get_policies, get_policy, get_scan_config, get_scan_configs, modify_policy,
    modify_scan_config, ConfigOpts, GetPolicyOpts, GetScanConfigsOpts,
};

#[test]
fn test_generic_configs_usage_type_xml() {
    assert_eq!(ConfigUsageType::Scan.as_gmp_str(), "scan");
    assert_eq!(ConfigUsageType::Policy.as_gmp_str(), "policy");
    assert_eq!(ConfigUsageType::custom("audit").as_gmp_str(), "audit");
}

#[test]
fn test_generic_configs_clone_create_xml() {
    assert_eq!(
        xml(clone_config(&id("c1"), CloneConfigOpts::default())),
        "<create_config><copy>c1</copy></create_config>"
    );
    assert_eq!(
        xml(clone_config(
            &id("c1"),
            CloneConfigOpts {
                name: Some("copy".into()),
            },
        )),
        "<create_config><copy>c1</copy><name>copy</name></create_config>"
    );
    assert_eq!(
        xml(create_config(CreateConfigOpts {
            name: "cfg".into(),
            base_id: Some(id("base1")),
            comment: Some("c".into()),
            usage_type: Some(ConfigUsageType::Scan),
        })),
        "<create_config><name>cfg</name><copy>base1</copy><comment>c</comment><usage_type>scan</usage_type></create_config>"
    );
}

#[test]
fn test_generic_configs_get_xml() {
    assert_eq!(
        xml(get_configs(GetConfigsOpts {
            filter_string: Some("name=foo".into()),
            filter_id: Some(id("f1")),
            trash: Some(false),
            details: Some(true),
            families: Some(true),
            preferences: Some(false),
            tasks: Some(true),
            usage_type: Some(ConfigUsageType::custom("policy")),
            ..Default::default()
        })),
        "<get_configs details=\"1\" families=\"1\" filt_id=\"f1\" filter=\"name=foo\" preferences=\"0\" tasks=\"1\" trash=\"0\" usage_type=\"policy\"/>"
    );
    assert_eq!(
        xml(get_config(
            &id("c1"),
            GetConfigOpts {
                usage_type: Some(ConfigUsageType::Policy),
                tasks: Some(true),
                ..Default::default()
            },
        )),
        "<get_configs config_id=\"c1\" details=\"1\" tasks=\"1\" usage_type=\"policy\"/>"
    );
    assert_eq!(
        xml(get_configs(GetConfigsOpts {
            usage_type: Some(ConfigUsageType::custom("")),
            ..Default::default()
        })),
        "<get_configs/>"
    );
}

#[test]
fn test_generic_configs_modify_delete_xml() {
    assert_eq!(
        xml(modify_config(
            &id("c1"),
            ModifyConfigOpts {
                name: Some("renamed".into()),
                comment: Some("updated".into()),
                usage_type: Some(ConfigUsageType::Policy),
            },
        )),
        "<modify_config config_id=\"c1\"><name>renamed</name><comment>updated</comment><usage_type>policy</usage_type></modify_config>"
    );
    assert_eq!(
        xml(delete_config(
            &id("c1"),
            DeleteConfigOpts {
                ultimate: Some(true),
            },
        )),
        "<delete_config config_id=\"c1\" ultimate=\"1\"/>"
    );
}

#[test]
fn test_scan_configs_wrappers_match_generic_xml() {
    assert_eq!(
        xml(clone_scan_config(&id("c1"))),
        xml(clone_config(&id("c1"), CloneConfigOpts::default()))
    );
    assert_eq!(
        xml(create_scan_config(
            "cfg",
            Some(&id("base1")),
            ConfigOpts {
                comment: Some("c".into()),
                usage_type: Some("scan".into()),
            },
        )),
        xml(create_config(CreateConfigOpts {
            name: "cfg".into(),
            base_id: Some(id("base1")),
            comment: Some("c".into()),
            usage_type: Some(ConfigUsageType::Scan),
        }))
    );
    assert_eq!(
        xml(get_scan_configs(GetScanConfigsOpts {
            filter_string: Some("name=foo".into()),
            details: Some(true),
            ..Default::default()
        })),
        xml(get_configs(GetConfigsOpts {
            filter_string: Some("name=foo".into()),
            details: Some(true),
            ..Default::default()
        }))
    );
    assert_eq!(
        xml(get_scan_config(&id("c1"))),
        xml(get_config(&id("c1"), GetConfigOpts::default()))
    );
    assert_eq!(
        xml(modify_scan_config(
            &id("c1"),
            ConfigOpts {
                comment: Some("updated".into()),
                usage_type: Some("scan".into()),
            },
        )),
        xml(modify_config(
            &id("c1"),
            ModifyConfigOpts {
                comment: Some("updated".into()),
                usage_type: Some(ConfigUsageType::Scan),
                ..Default::default()
            },
        ))
    );
    assert_eq!(
        xml(delete_scan_config(&id("c1"), true)),
        xml(delete_config(
            &id("c1"),
            DeleteConfigOpts {
                ultimate: Some(true),
            },
        ))
    );
}

#[test]
fn test_policies_wrappers_match_generic_xml() {
    assert_eq!(
        xml(clone_policy(&id("p1"))),
        xml(clone_config(&id("p1"), CloneConfigOpts::default()))
    );
    assert_eq!(
        xml(create_policy(
            "policy",
            ConfigOpts {
                comment: Some("audit baseline".into()),
                ..Default::default()
            },
        )),
        xml(create_config(CreateConfigOpts {
            name: "policy".into(),
            base_id: None,
            comment: Some("audit baseline".into()),
            usage_type: Some(ConfigUsageType::Policy),
        }))
    );
    assert_eq!(
        xml(get_policies(GetScanConfigsOpts::default())),
        xml(get_configs(GetConfigsOpts {
            usage_type: Some(ConfigUsageType::Policy),
            ..Default::default()
        }))
    );
    assert_eq!(
        xml(get_policy(&id("p1"), GetPolicyOpts { audits: Some(true) })),
        xml(get_config(
            &id("p1"),
            GetConfigOpts {
                usage_type: Some(ConfigUsageType::Policy),
                tasks: Some(true),
                ..Default::default()
            },
        ))
    );
    assert_eq!(
        xml(modify_policy(
            &id("p1"),
            ConfigOpts {
                comment: Some("updated".into()),
                ..Default::default()
            },
        )),
        xml(modify_config(
            &id("p1"),
            ModifyConfigOpts {
                comment: Some("updated".into()),
                usage_type: Some(ConfigUsageType::Policy),
                ..Default::default()
            },
        ))
    );
    assert_eq!(
        xml(delete_policy(&id("p1"))),
        xml(delete_config(
            &id("p1"),
            DeleteConfigOpts {
                ultimate: Some(false),
            },
        ))
    );
}
