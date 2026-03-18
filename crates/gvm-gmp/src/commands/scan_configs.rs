// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Scan configuration command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::commands::usage_type::UsageType;
use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::types::EntityId;

/// Optional fields for scan-configuration create and modify requests.
#[derive(Debug, Clone, Default)]
pub struct ConfigOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional usage type string.
    pub usage_type: Option<String>,
}

/// Options for `get_scan_configs` requests.
#[derive(Debug, Clone, Default)]
pub struct GetScanConfigsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Build a clone request for an existing scan config.
#[must_use]
pub fn clone_scan_config(config_id: &EntityId) -> impl Request {
    XmlCommand::new("create_config").child_with_text("copy", config_id.as_str())
}

/// Build a `create_scan_config` request.
#[must_use]
pub fn create_scan_config(
    name: &str,
    base_id: Option<&EntityId>,
    opts: ConfigOpts,
) -> impl Request {
    create_config_with_usage(name, base_id, opts, None)
}

fn create_config_with_usage(
    name: &str,
    base_id: Option<&EntityId>,
    opts: ConfigOpts,
    usage_type: Option<UsageType>,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_config");
    cmd.add_element_with_text("name", name);
    if let Some(base_id) = base_id {
        cmd.add_element("copy").set_text(base_id.as_str());
    }
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(usage_type) = usage_type {
        cmd.add_element_with_text("usage_type", usage_type.as_gmp_str());
    } else {
        add_text_element(&mut cmd, "usage_type", opts.usage_type.as_deref());
    }
    cmd
}

/// Build a `get_scan_configs` request.
#[must_use]
pub fn get_scan_configs(opts: GetScanConfigsOpts) -> impl Request {
    get_configs_with_usage(opts, None)
}

fn get_configs_with_usage(opts: GetScanConfigsOpts, usage_type: Option<UsageType>) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_configs");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    if let Some(usage_type) = usage_type {
        cmd.set_attribute("usage_type", usage_type.as_gmp_str());
    }
    cmd
}

/// Build a `get_scan_config` request.
#[must_use]
pub fn get_scan_config(config_id: &EntityId) -> impl Request {
    XmlCommand::new("get_configs")
        .attribute("config_id", config_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_scan_config` request.
#[must_use]
pub fn modify_scan_config(config_id: &EntityId, opts: ConfigOpts) -> impl Request {
    modify_config_with_usage(config_id, opts, None)
}

fn modify_config_with_usage(
    config_id: &EntityId,
    opts: ConfigOpts,
    usage_type: Option<UsageType>,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_config").attribute("config_id", config_id.as_str());
    add_text_element(&mut cmd, "name", Some(""));
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(usage_type) = usage_type {
        cmd.add_element_with_text("usage_type", usage_type.as_gmp_str());
    } else {
        add_text_element(&mut cmd, "usage_type", opts.usage_type.as_deref());
    }
    cmd
}

/// Build a `delete_scan_config` request.
#[must_use]
pub fn delete_scan_config(config_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_config")
        .attribute("config_id", config_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

/// Build a `sync_config` request.
#[must_use]
pub fn sync_config(config_id: &EntityId) -> impl Request {
    XmlCommand::new("sync_config").attribute("config_id", config_id.as_str())
}

/// Build a clone request for an existing policy.
#[must_use]
pub fn clone_policy(config_id: &EntityId) -> impl Request {
    clone_scan_config(config_id)
}

/// Build a `create_config` request for a policy.
#[must_use]
pub fn create_policy(name: &str, opts: ConfigOpts) -> impl Request {
    create_config_with_usage(name, None, opts, Some(UsageType::Policy))
}

/// Build a `get_configs` request scoped to policies.
#[must_use]
pub fn get_policies(opts: GetScanConfigsOpts) -> impl Request {
    get_configs_with_usage(opts, Some(UsageType::Policy))
}

/// Build a `modify_config` request scoped to policies.
#[must_use]
pub fn modify_policy(config_id: &EntityId, opts: ConfigOpts) -> impl Request {
    modify_config_with_usage(config_id, opts, Some(UsageType::Policy))
}

/// Build a `delete_config` request for a policy.
#[must_use]
pub fn delete_policy(config_id: &EntityId) -> impl Request {
    delete_scan_config(config_id, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn scan_config_commands_build_xml() {
        let rendered = xml(create_scan_config(
            "cfg",
            Some(&id("base1")),
            ConfigOpts {
                comment: Some("c".into()),
                usage_type: Some("scan".into()),
            },
        ));
        assert!(rendered.contains("<copy>base1</copy>"));
        assert_eq!(
            xml(clone_scan_config(&id("c1"))),
            "<create_config><copy>c1</copy></create_config>"
        );
        let rendered = xml(get_scan_config(&id("c1")));
        assert!(rendered.contains("<get_configs "));
        assert!(rendered.contains("config_id=\"c1\""));
        assert!(rendered.contains("details=\"1\""));
    }

    #[test]
    fn scan_config_get_modify_delete_sync_build_xml() {
        let rendered = xml(get_scan_configs(GetScanConfigsOpts {
            filter_string: Some("name=foo".into()),
            ..Default::default()
        }));
        assert!(rendered.contains("filter=\"name=foo\""));
        let rendered = xml(modify_scan_config(
            &id("c1"),
            ConfigOpts {
                comment: Some("updated".into()),
                ..Default::default()
            },
        ));
        assert_eq!(
            rendered,
            "<modify_config config_id=\"c1\"><comment>updated</comment></modify_config>"
        );
        assert_eq!(
            xml(delete_scan_config(&id("c1"), false)),
            "<delete_config config_id=\"c1\" ultimate=\"0\"/>"
        );
        assert_eq!(
            xml(sync_config(&id("c1"))),
            "<sync_config config_id=\"c1\"/>"
        );
    }

    #[test]
    fn policy_commands_build_xml() {
        assert_eq!(
            xml(create_policy(
                "policy",
                ConfigOpts {
                    comment: Some("audit baseline".into()),
                    ..Default::default()
                }
            )),
            "<create_config><name>policy</name><comment>audit baseline</comment><usage_type>policy</usage_type></create_config>"
        );
        assert_eq!(
            xml(get_policies(GetScanConfigsOpts::default())),
            "<get_configs usage_type=\"policy\"/>"
        );
        assert_eq!(
            xml(modify_policy(
                &id("p1"),
                ConfigOpts {
                    comment: Some("updated".into()),
                    ..Default::default()
                }
            )),
            "<modify_config config_id=\"p1\"><comment>updated</comment><usage_type>policy</usage_type></modify_config>"
        );
        assert_eq!(
            xml(delete_policy(&id("p1"))),
            "<delete_config config_id=\"p1\" ultimate=\"0\"/>"
        );
        assert_eq!(
            xml(clone_policy(&id("p1"))),
            "<create_config><copy>p1</copy></create_config>"
        );
    }
}
