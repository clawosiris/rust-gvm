// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Scan configuration command builders.

use base64::Engine as _;
use gvm_protocol::{xml_command::XmlElement, Request, XmlCommand};
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::commands::configs::{
    clone_config, create_config, delete_config, get_config, get_configs, modify_config,
    CloneConfigOpts, ConfigUsageType, CreateConfigOpts, DeleteConfigOpts, GetConfigOpts,
    GetConfigsOpts, ModifyConfigOpts,
};
use crate::commands::usage_type::UsageType;
use crate::common::bool_str;
use crate::responses::ParseError;
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

/// NVT family selection entry for scan-config and policy modify requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvtFamilySelection {
    /// NVT family name.
    pub name: String,
    /// Whether new NVTs should be added to this family automatically.
    pub growing: bool,
    /// Whether all NVTs from this family should be selected.
    pub all: bool,
}

/// Options for scan-config `get_preferences` requests.
#[derive(Debug, Clone, Default)]
pub struct GetScanConfigPreferencesOpts {
    /// Optional NVT OID to restrict preference lookup.
    pub nvt_oid: Option<String>,
    /// Optional scan-config identifier to request configured values.
    pub config_id: Option<EntityId>,
}

/// Options for singular policy `get_configs` requests.
#[derive(Debug, Clone, Default)]
pub struct GetPolicyOpts {
    /// Whether to include audits using this policy.
    pub audits: Option<bool>,
}

/// Build a clone request for an existing scan config.
#[must_use]
pub fn clone_scan_config(config_id: &EntityId) -> impl Request {
    clone_config(config_id, CloneConfigOpts::default())
}

/// Build a `create_scan_config` request.
#[must_use]
pub fn create_scan_config(
    name: &str,
    base_id: Option<&EntityId>,
    opts: ConfigOpts,
) -> impl Request {
    create_config(CreateConfigOpts {
        name: name.into(),
        base_id: base_id.cloned(),
        comment: opts.comment,
        usage_type: opts.usage_type.map(ConfigUsageType::custom),
    })
}

/// Build a `create_config` request that imports scan-config XML.
///
/// # Errors
/// Returns an error if `scan_config_xml` is not a single well-formed XML
/// document rooted at `get_configs_response`.
pub fn import_scan_config(scan_config_xml: &str) -> Result<impl Request, ParseError> {
    validate_scan_config_import_xml(scan_config_xml)?;
    let mut request =
        Vec::with_capacity("<create_config></create_config>".len() + scan_config_xml.len());
    request.extend_from_slice(b"<create_config>");
    request.extend_from_slice(scan_config_xml.as_bytes());
    request.extend_from_slice(b"</create_config>");
    Ok(request)
}

/// Build a `get_scan_configs` request.
#[must_use]
pub fn get_scan_configs(opts: GetScanConfigsOpts) -> impl Request {
    get_configs(GetConfigsOpts {
        filter_string: opts.filter_string,
        filter_id: opts.filter_id,
        trash: opts.trash,
        details: opts.details,
        usage_type: Some(ConfigUsageType::from(UsageType::Scan)),
        ..Default::default()
    })
}

/// Build a `get_scan_config` request.
#[must_use]
pub fn get_scan_config(config_id: &EntityId) -> impl Request {
    get_config(
        config_id,
        GetConfigOpts {
            usage_type: Some(ConfigUsageType::from(UsageType::Scan)),
            ..Default::default()
        },
    )
}

/// Build a `get_preferences` request for scan-config preferences.
#[must_use]
pub fn get_scan_config_preferences(opts: GetScanConfigPreferencesOpts) -> impl Request {
    get_preferences_with(
        None,
        opts.nvt_oid.as_deref(),
        opts.config_id.as_ref().map(EntityId::as_str),
    )
}

/// Build a `get_preferences` request for a single scan-config preference.
#[must_use]
pub fn get_scan_config_preference(name: &str, opts: GetScanConfigPreferencesOpts) -> impl Request {
    get_preferences_with(
        Some(name),
        opts.nvt_oid.as_deref(),
        opts.config_id.as_ref().map(EntityId::as_str),
    )
}

fn get_preferences_with(
    preference: Option<&str>,
    nvt_oid: Option<&str>,
    config_id: Option<&str>,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_preferences");
    if let Some(preference) = preference {
        cmd.set_attribute("preference", preference);
    }
    if let Some(nvt_oid) = nvt_oid {
        cmd.set_attribute("nvt_oid", nvt_oid);
    }
    if let Some(config_id) = config_id {
        cmd.set_attribute("config_id", config_id);
    }
    cmd
}

/// Build a `modify_scan_config` request.
#[must_use]
pub fn modify_scan_config(config_id: &EntityId, opts: ConfigOpts) -> impl Request {
    modify_config(
        config_id,
        ModifyConfigOpts {
            comment: normalize_optional_text(opts.comment),
            usage_type: opts.usage_type.map(ConfigUsageType::custom),
            ..Default::default()
        },
    )
}

/// Build a `modify_config` request that sets a scan-config NVT preference.
///
/// Pass `None` for `value` to delete the configured value and fall back to the
/// default preference.
#[must_use]
pub fn modify_scan_config_set_nvt_preference(
    config_id: &EntityId,
    name: &str,
    nvt_oid: &str,
    value: Option<&str>,
) -> impl Request {
    modify_config_set_nvt_preference(config_id, name, nvt_oid, value)
}

/// Build a `modify_config` request that sets a scan-config scanner preference.
///
/// Pass `None` for `value` to delete the configured value and fall back to the
/// default preference.
#[must_use]
pub fn modify_scan_config_set_scanner_preference(
    config_id: &EntityId,
    name: &str,
    value: Option<&str>,
) -> impl Request {
    modify_config_set_scanner_preference(config_id, name, value)
}

/// Build a `modify_config` request that replaces a scan-config family NVT selection.
#[must_use]
pub fn modify_scan_config_set_nvt_selection(
    config_id: &EntityId,
    family: &str,
    nvt_oids: &[String],
) -> impl Request {
    modify_config_set_nvt_selection(config_id, family, nvt_oids)
}

/// Build a `modify_config` request that replaces scan-config family selection.
#[must_use]
pub fn modify_scan_config_set_family_selection(
    config_id: &EntityId,
    families: &[NvtFamilySelection],
    auto_add_new_families: bool,
) -> impl Request {
    modify_config_set_family_selection(config_id, families, auto_add_new_families)
}

/// Build a `modify_config` request that sets a scan-config name.
#[must_use]
pub fn modify_scan_config_set_name(config_id: &EntityId, name: &str) -> impl Request {
    modify_config_set_name(config_id, name)
}

/// Build a `modify_config` request that sets or clears a scan-config comment.
#[must_use]
pub fn modify_scan_config_set_comment(config_id: &EntityId, comment: Option<&str>) -> impl Request {
    modify_config_set_comment(config_id, comment)
}

fn modify_config_set_nvt_preference(
    config_id: &EntityId,
    name: &str,
    nvt_oid: &str,
    value: Option<&str>,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_config").attribute("config_id", config_id.as_str());
    let preference = cmd.add_element("preference");
    preference.add_child("nvt").set_attribute("oid", nvt_oid);
    preference.add_child_with_text("name", name);
    add_encoded_preference_value(preference, value);
    cmd
}

fn modify_config_set_scanner_preference(
    config_id: &EntityId,
    name: &str,
    value: Option<&str>,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_config").attribute("config_id", config_id.as_str());
    let preference = cmd.add_element("preference");
    preference.add_child_with_text("name", name);
    add_encoded_preference_value(preference, value);
    cmd
}

fn modify_config_set_nvt_selection(
    config_id: &EntityId,
    family: &str,
    nvt_oids: &[String],
) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_config").attribute("config_id", config_id.as_str());
    let nvt_selection = cmd.add_element("nvt_selection");
    nvt_selection.add_child_with_text("family", family);
    for nvt_oid in nvt_oids {
        nvt_selection.add_child("nvt").set_attribute("oid", nvt_oid);
    }
    cmd
}

fn modify_config_set_family_selection(
    config_id: &EntityId,
    families: &[NvtFamilySelection],
    auto_add_new_families: bool,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_config").attribute("config_id", config_id.as_str());
    let family_selection = cmd.add_element("family_selection");
    family_selection.add_child_with_text("growing", bool_str(auto_add_new_families));
    for family in families {
        let family_element = family_selection.add_child("family");
        family_element.add_child_with_text("name", &family.name);
        family_element.add_child_with_text("all", bool_str(family.all));
        family_element.add_child_with_text("growing", bool_str(family.growing));
    }
    cmd
}

fn add_encoded_preference_value(preference: &mut XmlElement, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
        preference.add_child_with_text("value", &encoded);
    }
}

fn modify_config_set_name(config_id: &EntityId, name: &str) -> XmlCommand {
    XmlCommand::new("modify_config")
        .attribute("config_id", config_id.as_str())
        .child_with_text("name", name)
}

fn modify_config_set_comment(config_id: &EntityId, comment: Option<&str>) -> XmlCommand {
    XmlCommand::new("modify_config")
        .attribute("config_id", config_id.as_str())
        .child_with_text("comment", comment.unwrap_or_default())
}

/// Build a `delete_scan_config` request.
#[must_use]
pub fn delete_scan_config(config_id: &EntityId, ultimate: bool) -> impl Request {
    delete_config(
        config_id,
        DeleteConfigOpts {
            ultimate: Some(ultimate),
        },
    )
}

/// Build the global, parameterless `sync_config` request.
#[must_use]
pub fn sync_config() -> impl Request {
    XmlCommand::new("sync_config")
}

/// Build a clone request for an existing policy.
#[must_use]
pub fn clone_policy(config_id: &EntityId) -> impl Request {
    clone_scan_config(config_id)
}

/// Build a `create_config` request for a policy.
#[must_use]
pub fn create_policy(name: &str, opts: ConfigOpts) -> impl Request {
    create_config(CreateConfigOpts {
        name: name.into(),
        base_id: None,
        comment: opts.comment,
        usage_type: Some(ConfigUsageType::from(UsageType::Policy)),
    })
}

/// Build a `create_config` request that imports policy XML.
///
/// # Errors
/// Returns an error if `policy_xml` is not a single well-formed XML document
/// rooted at `get_configs_response`.
pub fn import_policy(policy_xml: &str) -> Result<impl Request, ParseError> {
    validate_policy_import_xml(policy_xml)?;
    let policy_xml = strip_leading_xml_declaration(policy_xml);
    let mut request =
        Vec::with_capacity("<create_config></create_config>".len() + policy_xml.len());
    request.extend_from_slice(b"<create_config>");
    request.extend_from_slice(policy_xml.as_bytes());
    request.extend_from_slice(b"</create_config>");
    Ok(request)
}

/// Build a `get_configs` request scoped to policies.
#[must_use]
pub fn get_policies(opts: GetScanConfigsOpts) -> impl Request {
    get_configs(GetConfigsOpts {
        filter_string: opts.filter_string,
        filter_id: opts.filter_id,
        trash: opts.trash,
        details: opts.details,
        usage_type: Some(ConfigUsageType::from(UsageType::Policy)),
        ..Default::default()
    })
}

/// Build a `get_configs` request for a single policy.
#[must_use]
pub fn get_policy(policy_id: &EntityId, opts: GetPolicyOpts) -> impl Request {
    get_config(
        policy_id,
        GetConfigOpts {
            usage_type: Some(ConfigUsageType::from(UsageType::Policy)),
            tasks: opts.audits,
            ..Default::default()
        },
    )
}

/// Build a `modify_config` request scoped to policies.
#[must_use]
pub fn modify_policy(config_id: &EntityId, opts: ConfigOpts) -> impl Request {
    modify_config(
        config_id,
        ModifyConfigOpts {
            comment: normalize_optional_text(opts.comment),
            usage_type: Some(ConfigUsageType::from(UsageType::Policy)),
            ..Default::default()
        },
    )
}

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

fn validate_policy_import_xml(xml: &str) -> Result<(), ParseError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    reader.config_mut().check_comments = true;
    let mut depth = 0usize;
    let mut saw_root = false;
    let mut completed_root = false;

    loop {
        match reader.read_event()? {
            Event::Start(event) => {
                if completed_root {
                    return invalid_policy_xml("multiple root elements");
                }
                if !saw_root {
                    validate_policy_import_root(event.name().as_ref())?;
                    saw_root = true;
                }
                depth += 1;
            }
            Event::Empty(event) if depth == 0 => {
                if completed_root {
                    return invalid_policy_xml("multiple root elements");
                }
                completed_root = true;
                saw_root = true;
                validate_policy_import_root(event.name().as_ref())?;
            }
            Event::End(_) => {
                depth = depth.checked_sub(1).ok_or(ParseError::InvalidValue {
                    field: "policy_xml".to_string(),
                    value: "unmatched end tag".to_string(),
                })?;
                if depth == 0 {
                    completed_root = true;
                }
            }
            Event::Text(event) if depth == 0 && !event.as_ref().trim().is_empty() => {
                return invalid_policy_xml(if completed_root {
                    "text after root element"
                } else {
                    "text before root element"
                });
            }
            Event::CData(_) | Event::GeneralRef(_) if depth == 0 => {
                return invalid_policy_xml("content outside root element");
            }
            Event::Decl(_) if saw_root || completed_root || depth != 0 => {
                return invalid_policy_xml("XML declaration outside document prolog");
            }
            Event::DocType(_) => return invalid_policy_xml("DOCTYPE is not allowed"),
            Event::Eof => {
                if saw_root && depth == 0 {
                    return Ok(());
                }
                return Err(ParseError::MissingElement(
                    "get_configs_response".to_string(),
                ));
            }
            _ => {}
        }
    }
}

fn strip_leading_xml_declaration(xml: &str) -> &str {
    xml.strip_prefix("<?xml")
        .and_then(|rest| rest.find("?>").map(|end| &rest[end + 2..]))
        .unwrap_or(xml)
}

fn validate_policy_import_root(root: &str) -> Result<(), ParseError> {
    if root == "get_configs_response" {
        Ok(())
    } else {
        invalid_policy_xml("root element must be get_configs_response")
    }
}

fn invalid_policy_xml<T>(value: &str) -> Result<T, ParseError> {
    Err(ParseError::InvalidValue {
        field: "policy_xml".to_string(),
        value: value.to_string(),
    })
}

fn validate_scan_config_import_xml(xml: &str) -> Result<(), ParseError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    reader.config_mut().check_comments = true;
    let mut depth = 0usize;
    let mut saw_root = false;
    let mut completed_root = false;

    loop {
        match reader.read_event()? {
            Event::Start(event) => {
                if completed_root {
                    return invalid_scan_config_xml("multiple root elements");
                }
                if !saw_root {
                    validate_scan_config_import_root(event.name().as_ref())?;
                    saw_root = true;
                }
                depth += 1;
            }
            Event::Empty(event) if depth == 0 => {
                if completed_root {
                    return invalid_scan_config_xml("multiple root elements");
                }
                completed_root = true;
                saw_root = true;
                validate_scan_config_import_root(event.name().as_ref())?;
            }
            Event::End(_) => {
                depth = depth.checked_sub(1).ok_or(ParseError::InvalidValue {
                    field: "scan_config_xml".to_string(),
                    value: "unmatched end tag".to_string(),
                })?;
                if depth == 0 {
                    completed_root = true;
                }
            }
            Event::Text(event) if depth == 0 && !event.as_ref().trim().is_empty() => {
                return invalid_scan_config_xml(if completed_root {
                    "text after root element"
                } else {
                    "text before root element"
                });
            }
            Event::CData(_) | Event::GeneralRef(_) if depth == 0 => {
                return invalid_scan_config_xml("content outside root element");
            }
            Event::Decl(_) => return invalid_scan_config_xml("XML declaration is not allowed"),
            Event::DocType(_) => return invalid_scan_config_xml("DOCTYPE is not allowed"),
            Event::Eof => {
                if saw_root && depth == 0 {
                    return Ok(());
                }
                return Err(ParseError::MissingElement(
                    "get_configs_response".to_string(),
                ));
            }
            _ => {}
        }
    }
}

fn validate_scan_config_import_root(root: &str) -> Result<(), ParseError> {
    if root == "get_configs_response" {
        Ok(())
    } else {
        invalid_scan_config_xml("root element must be get_configs_response")
    }
}

fn invalid_scan_config_xml<T>(value: &str) -> Result<T, ParseError> {
    Err(ParseError::InvalidValue {
        field: "scan_config_xml".to_string(),
        value: value.to_string(),
    })
}

/// Build a `modify_config` request that sets a policy NVT preference.
///
/// Pass `None` for `value` to delete the configured value and fall back to the
/// default preference.
#[must_use]
pub fn modify_policy_set_nvt_preference(
    policy_id: &EntityId,
    name: &str,
    nvt_oid: &str,
    value: Option<&str>,
) -> impl Request {
    modify_config_set_nvt_preference(policy_id, name, nvt_oid, value)
}

/// Build a `modify_config` request that sets a policy scanner preference.
///
/// Pass `None` for `value` to delete the configured value and fall back to the
/// default preference.
#[must_use]
pub fn modify_policy_set_scanner_preference(
    policy_id: &EntityId,
    name: &str,
    value: Option<&str>,
) -> impl Request {
    modify_config_set_scanner_preference(policy_id, name, value)
}

/// Build a `modify_config` request that replaces a policy family NVT selection.
#[must_use]
pub fn modify_policy_set_nvt_selection(
    policy_id: &EntityId,
    family: &str,
    nvt_oids: &[String],
) -> impl Request {
    modify_config_set_nvt_selection(policy_id, family, nvt_oids)
}

/// Build a `modify_config` request that replaces policy family selection.
#[must_use]
pub fn modify_policy_set_family_selection(
    policy_id: &EntityId,
    families: &[NvtFamilySelection],
    auto_add_new_families: bool,
) -> impl Request {
    modify_config_set_family_selection(policy_id, families, auto_add_new_families)
}

/// Build a `modify_config` request that sets a policy name.
#[must_use]
pub fn modify_policy_set_name(policy_id: &EntityId, name: &str) -> impl Request {
    modify_config_set_name(policy_id, name)
}

/// Build a `modify_config` request that sets or clears a policy comment.
#[must_use]
pub fn modify_policy_set_comment(policy_id: &EntityId, comment: Option<&str>) -> impl Request {
    modify_config_set_comment(policy_id, comment)
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
    fn scan_config_preference_commands_build_xml() {
        assert_eq!(
            xml(get_scan_config_preferences(
                GetScanConfigPreferencesOpts::default()
            )),
            "<get_preferences/>"
        );
        assert_eq!(
            xml(get_scan_config_preferences(GetScanConfigPreferencesOpts {
                nvt_oid: Some("1.3.6.1".into()),
                config_id: Some(id("c1")),
            })),
            "<get_preferences config_id=\"c1\" nvt_oid=\"1.3.6.1\"/>"
        );
        assert_eq!(
            xml(get_scan_config_preference(
                "timeout",
                GetScanConfigPreferencesOpts {
                    nvt_oid: Some("1.3.6.1".into()),
                    config_id: Some(id("c1")),
                }
            )),
            "<get_preferences config_id=\"c1\" nvt_oid=\"1.3.6.1\" preference=\"timeout\"/>"
        );
    }

    #[test]
    fn scan_config_get_modify_delete_sync_build_xml() {
        assert_eq!(
            xml(get_scan_configs(GetScanConfigsOpts::default())),
            "<get_configs usage_type=\"scan\"/>"
        );
        let rendered = xml(get_scan_configs(GetScanConfigsOpts {
            filter_string: Some("name=foo".into()),
            ..Default::default()
        }));
        assert_eq!(
            rendered,
            "<get_configs filter=\"name=foo\" usage_type=\"scan\"/>"
        );
        assert_eq!(
            xml(get_scan_config(&id("c1"))),
            "<get_configs config_id=\"c1\" details=\"1\" usage_type=\"scan\"/>"
        );
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
            xml(modify_scan_config_set_name(&id("c1"), "renamed")),
            "<modify_config config_id=\"c1\"><name>renamed</name></modify_config>"
        );
        assert_eq!(
            xml(modify_scan_config_set_comment(&id("c1"), Some("updated"))),
            "<modify_config config_id=\"c1\"><comment>updated</comment></modify_config>"
        );
        assert_eq!(
            xml(modify_scan_config_set_comment(&id("c1"), None)),
            "<modify_config config_id=\"c1\"><comment></comment></modify_config>"
        );
        assert_eq!(
            xml(delete_scan_config(&id("c1"), false)),
            "<delete_config config_id=\"c1\" ultimate=\"0\"/>"
        );
        assert_eq!(xml(sync_config()), "<sync_config/>");
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
            xml(get_policy(&id("p1"), GetPolicyOpts::default())),
            "<get_configs config_id=\"p1\" details=\"1\" usage_type=\"policy\"/>"
        );
        assert_eq!(
            xml(get_policy(&id("p1"), GetPolicyOpts { audits: Some(true) })),
            "<get_configs config_id=\"p1\" details=\"1\" tasks=\"1\" usage_type=\"policy\"/>"
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
            xml(modify_policy_set_name(&id("p1"), "renamed")),
            "<modify_config config_id=\"p1\"><name>renamed</name></modify_config>"
        );
        assert_eq!(
            xml(modify_policy_set_comment(&id("p1"), Some("updated"))),
            "<modify_config config_id=\"p1\"><comment>updated</comment></modify_config>"
        );
        assert_eq!(
            xml(modify_policy_set_comment(&id("p1"), None)),
            "<modify_config config_id=\"p1\"><comment></comment></modify_config>"
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
