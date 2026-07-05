// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Generic GMP config command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, set_optional_bool_attr};
use crate::types::EntityId;

/// Typed GMP config usage-type values.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConfigUsageType {
    /// Standard scan configs.
    Scan,
    /// Policy configs.
    Policy,
    /// Forward-compatible custom usage type.
    Custom(String),
}

impl ConfigUsageType {
    /// Build a custom/unknown config usage-type value.
    #[must_use]
    pub fn custom(value: impl Into<String>) -> Self {
        Self::Custom(value.into())
    }

    /// Returns the GMP wire-format string for this value.
    #[must_use]
    pub fn as_gmp_str(&self) -> &str {
        match self {
            Self::Scan => "scan",
            Self::Policy => "policy",
            Self::Custom(value) => value.as_str(),
        }
    }
}

/// Options for `clone_config` requests.
#[derive(Debug, Clone, Default)]
pub struct CloneConfigOpts {
    /// Optional cloned config name.
    pub name: Option<String>,
}

/// Options for `create_config` requests.
#[derive(Debug, Clone)]
pub struct CreateConfigOpts {
    /// Config name.
    pub name: String,
    /// Optional base config identifier to copy.
    pub base_id: Option<EntityId>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional config usage type.
    pub usage_type: Option<ConfigUsageType>,
}

/// Options for `get_configs` requests.
#[derive(Debug, Clone, Default)]
pub struct GetConfigsOpts {
    /// Optional config identifier.
    pub config_id: Option<EntityId>,
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
    /// Whether to include families.
    pub families: Option<bool>,
    /// Whether to include preferences.
    pub preferences: Option<bool>,
    /// Whether to include tasks/audits using this config.
    pub tasks: Option<bool>,
    /// Optional config usage type.
    pub usage_type: Option<ConfigUsageType>,
}

/// Options for singular `get_config` requests.
#[derive(Debug, Clone)]
pub struct GetConfigOpts {
    /// Whether to request detailed output.
    pub details: Option<bool>,
    /// Whether to include families.
    pub families: Option<bool>,
    /// Whether to include preferences.
    pub preferences: Option<bool>,
    /// Whether to include tasks/audits using this config.
    pub tasks: Option<bool>,
    /// Optional config usage type.
    pub usage_type: Option<ConfigUsageType>,
}

impl Default for GetConfigOpts {
    fn default() -> Self {
        Self {
            details: Some(true),
            families: None,
            preferences: None,
            tasks: None,
            usage_type: None,
        }
    }
}

/// Options for `modify_config` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyConfigOpts {
    /// Optional config name.
    pub name: Option<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional config usage type.
    pub usage_type: Option<ConfigUsageType>,
}

/// Options for `delete_config` requests.
#[derive(Debug, Clone, Default)]
pub struct DeleteConfigOpts {
    /// Whether to permanently delete the config.
    pub ultimate: Option<bool>,
}

/// Build a generic clone request for an existing config.
#[must_use]
pub fn clone_config(config_id: &EntityId, opts: CloneConfigOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_config");
    cmd.add_element_with_text("copy", config_id.as_str());
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    cmd
}

/// Build a generic `create_config` request.
#[must_use]
pub fn create_config(opts: CreateConfigOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_config");
    cmd.add_element_with_text("name", &opts.name);
    if let Some(base_id) = opts.base_id.as_ref() {
        cmd.add_element_with_text("copy", base_id.as_str());
    }
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    add_usage_type_element(&mut cmd, opts.usage_type.as_ref());
    cmd
}

/// Build a generic `get_configs` request.
#[must_use]
pub fn get_configs(opts: GetConfigsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_configs");
    if let Some(config_id) = opts.config_id.as_ref() {
        cmd.set_attribute("config_id", config_id.as_str());
    }
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    set_optional_bool_attr(&mut cmd, "families", opts.families);
    set_optional_bool_attr(&mut cmd, "preferences", opts.preferences);
    set_optional_bool_attr(&mut cmd, "tasks", opts.tasks);
    set_usage_type_attr(&mut cmd, opts.usage_type.as_ref());
    cmd
}

/// Build a generic singular `get_configs` request for one config.
#[must_use]
pub fn get_config(config_id: &EntityId, opts: GetConfigOpts) -> impl Request {
    get_configs(GetConfigsOpts {
        config_id: Some(config_id.clone()),
        details: opts.details,
        families: opts.families,
        preferences: opts.preferences,
        tasks: opts.tasks,
        usage_type: opts.usage_type,
        ..Default::default()
    })
}

/// Build a generic `modify_config` request.
#[must_use]
pub fn modify_config(config_id: &EntityId, opts: ModifyConfigOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_config").attribute("config_id", config_id.as_str());
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    add_usage_type_element(&mut cmd, opts.usage_type.as_ref());
    cmd
}

/// Build a generic `delete_config` request.
#[must_use]
pub fn delete_config(config_id: &EntityId, opts: DeleteConfigOpts) -> impl Request {
    let mut cmd = XmlCommand::new("delete_config").attribute("config_id", config_id.as_str());
    set_optional_bool_attr(&mut cmd, "ultimate", opts.ultimate);
    cmd
}

fn add_usage_type_element(cmd: &mut XmlCommand, usage_type: Option<&ConfigUsageType>) {
    if let Some(usage_type) = usage_type {
        add_text_element(cmd, "usage_type", Some(usage_type.as_gmp_str()));
    }
}

fn set_usage_type_attr(cmd: &mut XmlCommand, usage_type: Option<&ConfigUsageType>) {
    if let Some(value) = usage_type
        .map(ConfigUsageType::as_gmp_str)
        .filter(|value| !value.is_empty())
    {
        cmd.set_attribute("usage_type", value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn config_usage_type_maps_to_wire_values() {
        assert_eq!(ConfigUsageType::Scan.as_gmp_str(), "scan");
        assert_eq!(ConfigUsageType::Policy.as_gmp_str(), "policy");
        assert_eq!(ConfigUsageType::custom("audit").as_gmp_str(), "audit");
    }

    #[test]
    fn clone_create_config_build_xml() {
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
    fn get_config_variants_build_xml() {
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
    fn modify_delete_config_build_xml() {
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
        assert_eq!(
            xml(delete_config(&id("c1"), DeleteConfigOpts::default())),
            "<delete_config config_id=\"c1\"/>"
        );
    }
}
