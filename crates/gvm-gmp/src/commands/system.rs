// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! System-level command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::commands::user_settings::{modify_user_setting, ModifyUserSettingOpts};
use crate::common::add_filter_attrs;
use crate::enums::{AggregateStatistic, FeedType, HelpFormat, InfoType, ResourceType, SortOrder};
use crate::responses::{
    ActionResponse, DescribeAuthResponse, GetAggregatesResponse, GetFeedsResponse, GetInfoResponse,
    GetResourceNamesResponse, GetScanConfigPreferencesResponse, GetSettingsResponse,
    GetTimezonesResponse, GetVulnerabilitiesResponse, HelpResponse,
};
use crate::types::EntityId;
use crate::GmpRequest;

pub use super::system_reports::{get_system_reports, GetSystemReportsOpts};

/// Legacy system-module options for `get_aggregates` requests.
///
/// This type and [`get_aggregates`] are retained for source compatibility.
/// They predate current gvmd's required aggregate resource type. New code
/// should use [`crate::commands::aggregates::get_aggregates_request`].
#[derive(Debug, Clone, Default)]
pub struct GetAggregatesOpts {
    /// Optional aggregate data column.
    pub data_column: Option<String>,
    /// Optional aggregate group-by column.
    pub group_column: Option<String>,
    /// Optional aggregate statistic.
    pub statistic: Option<AggregateStatistic>,
    /// Optional aggregate sort field.
    pub sort_field: Option<String>,
    /// Optional sort order.
    pub sort_order: Option<SortOrder>,
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
}

/// Options for `get_feeds` requests.
#[derive(Debug, Clone, Default)]
pub struct GetFeedsOpts {
    /// Optional feed type.
    pub feed_type: Option<FeedType>,
}

/// Options for `get_info` requests.
#[derive(Debug, Clone, Default)]
pub struct GetInfoOpts {
    /// Optional info type.
    pub info_type: Option<InfoType>,
    /// Optional info object identifier.
    pub info_id: Option<EntityId>,
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
}

/// Options for `get_resource_names` requests.
#[derive(Debug, Clone, Default)]
pub struct GetResourceNamesOpts {
    /// Optional related resource type.
    pub resource_type: Option<ResourceType>,
    /// Optional related resource identifier.
    pub resource_id: Option<EntityId>,
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
}

/// Shared filter options for simple getter requests.
#[derive(Debug, Clone, Default)]
pub struct FilteredGetOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
}

/// Options for `modify_license` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyLicenseOpts {
    /// Whether gvmd may accept an empty license file.
    pub allow_empty: Option<bool>,
}

/// Options for `run_wizard` requests.
#[derive(Debug, Clone, Default)]
pub struct RunWizardOpts {
    /// Optional wizard execution mode.
    pub mode: Option<String>,
    /// Whether gvmd may only run a wizard marked as read-only.
    pub read_only: Option<bool>,
}

/// Semantic compatibility request for the system-module [`help`] builder.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemHelpRequest(Option<HelpFormat>);

impl SystemHelpRequest {
    /// Create a system-module help request.
    #[must_use]
    pub const fn new(format: Option<HelpFormat>) -> Self {
        Self(format)
    }
}

impl Request for SystemHelpRequest {
    fn to_bytes(&self) -> Vec<u8> {
        help(self.0).to_bytes()
    }
}

impl GmpRequest for SystemHelpRequest {
    type Response = HelpResponse;
}

/// Semantic compatibility request for the system-module [`get_feeds`] builder.
#[derive(Debug, Clone, Default)]
pub struct GetSystemFeedsRequest(GetFeedsOpts);

impl GetSystemFeedsRequest {
    /// Create a system-module feed request.
    #[must_use]
    pub fn new(opts: GetFeedsOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetSystemFeedsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_feeds(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetSystemFeedsRequest {
    type Response = GetFeedsResponse;
}

/// Semantic request for filtered setting discovery.
#[derive(Debug, Clone, Default)]
pub struct GetSettingsRequest(FilteredGetOpts);

impl GetSettingsRequest {
    /// Create a filtered setting request.
    #[must_use]
    pub fn new(opts: FilteredGetOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetSettingsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_settings(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetSettingsRequest {
    type Response = GetSettingsResponse;
}

/// Semantic request for timezone discovery.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetTimezonesRequest;

impl GetTimezonesRequest {
    /// Create a timezone-discovery request.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Request for GetTimezonesRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_timezones().to_bytes()
    }
}

impl GmpRequest for GetTimezonesRequest {
    type Response = GetTimezonesResponse;
}

/// Semantic compatibility request for the legacy system aggregate builder.
#[derive(Debug, Clone, Default)]
pub struct GetSystemAggregatesRequest(GetAggregatesOpts);

impl GetSystemAggregatesRequest {
    /// Create a legacy system aggregate request.
    #[must_use]
    pub fn new(opts: GetAggregatesOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetSystemAggregatesRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_aggregates(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetSystemAggregatesRequest {
    type Response = GetAggregatesResponse;
}

/// Semantic compatibility request for the system-module [`get_info`] builder.
#[derive(Debug, Clone, Default)]
pub struct GetSystemInfoRequest(GetInfoOpts);

impl GetSystemInfoRequest {
    /// Create a generic system information request.
    #[must_use]
    pub fn new(opts: GetInfoOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetSystemInfoRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_info(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetSystemInfoRequest {
    type Response = GetInfoResponse;
}

/// Semantic compatibility request for the system-module preference builder.
#[derive(Debug, Clone, Default)]
pub struct GetSystemPreferencesRequest(FilteredGetOpts);

impl GetSystemPreferencesRequest {
    /// Create a filtered preference request.
    #[must_use]
    pub fn new(opts: FilteredGetOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetSystemPreferencesRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_preferences(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetSystemPreferencesRequest {
    type Response = GetScanConfigPreferencesResponse;
}

/// Semantic request for resource-name discovery.
#[derive(Debug, Clone, Default)]
pub struct GetResourceNamesRequest(GetResourceNamesOpts);

impl GetResourceNamesRequest {
    /// Create a resource-name list request.
    #[must_use]
    pub fn new(opts: GetResourceNamesOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetResourceNamesRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_resource_names(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetResourceNamesRequest {
    type Response = GetResourceNamesResponse;
}

/// Semantic request for one resource name.
#[derive(Debug, Clone)]
pub struct GetResourceNameRequest {
    resource_id: EntityId,
    resource_type: ResourceType,
}

impl GetResourceNameRequest {
    /// Create a single-resource name request.
    #[must_use]
    pub fn new(resource_id: EntityId, resource_type: ResourceType) -> Self {
        Self {
            resource_id,
            resource_type,
        }
    }
}

impl Request for GetResourceNameRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_resource_name(&self.resource_id, self.resource_type).to_bytes()
    }
}

impl GmpRequest for GetResourceNameRequest {
    type Response = GetResourceNamesResponse;
}

/// Semantic request for vulnerability discovery.
#[derive(Debug, Clone, Default)]
pub struct GetVulnsRequest(FilteredGetOpts);

impl GetVulnsRequest {
    /// Create a vulnerability list request.
    #[must_use]
    pub fn new(opts: FilteredGetOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetVulnsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_vulns(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetVulnsRequest {
    type Response = GetVulnerabilitiesResponse;
}

/// Semantic request for one vulnerability using [`get_vuln`].
#[derive(Debug, Clone)]
pub struct GetVulnRequest(String);

impl GetVulnRequest {
    /// Create a single-vulnerability request.
    #[must_use]
    pub fn new(vuln_id: impl Into<String>) -> Self {
        Self(vuln_id.into())
    }
}

impl Request for GetVulnRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_vuln(&self.0).to_bytes()
    }
}

impl GmpRequest for GetVulnRequest {
    type Response = GetVulnerabilitiesResponse;
}

/// Semantic compatibility request for [`get_vulnerability`].
#[derive(Debug, Clone)]
pub struct GetVulnerabilityRequest(String);

impl GetVulnerabilityRequest {
    /// Create a descriptive-alias vulnerability request.
    #[must_use]
    pub fn new(vulnerability_id: impl Into<String>) -> Self {
        Self(vulnerability_id.into())
    }
}

impl Request for GetVulnerabilityRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_vulnerability(&self.0).to_bytes()
    }
}

impl GmpRequest for GetVulnerabilityRequest {
    type Response = GetVulnerabilitiesResponse;
}

/// Semantic request for license discovery.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetLicenseRequest;

impl GetLicenseRequest {
    /// Create a license-discovery request.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Request for GetLicenseRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_license().to_bytes()
    }
}

impl GmpRequest for GetLicenseRequest {
    type Response = ActionResponse;
}

/// Semantic request for authentication-configuration discovery.
#[derive(Debug, Clone, Copy, Default)]
pub struct DescribeAuthRequest;

impl DescribeAuthRequest {
    /// Create an authentication-description request.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Request for DescribeAuthRequest {
    fn to_bytes(&self) -> Vec<u8> {
        describe_auth().to_bytes()
    }
}

impl GmpRequest for DescribeAuthRequest {
    type Response = DescribeAuthResponse;
}

/// Build a `help` request.
#[must_use]
pub fn help(format: Option<HelpFormat>) -> impl Request {
    match format {
        Some(format) => {
            crate::commands::help::help_with_mode(crate::commands::help::HelpMode::Schema(format))
        }
        None => crate::commands::help::help_with_mode(crate::commands::help::HelpMode::Text),
    }
}

/// Build a `get_feeds` request.
#[must_use]
pub fn get_feeds(opts: GetFeedsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_feeds");
    if let Some(feed_type) = opts.feed_type {
        cmd.set_attribute("type", feed_type.as_gmp_str());
    }
    cmd
}

/// Build a `get_settings` request.
#[must_use]
pub fn get_settings(opts: FilteredGetOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_settings");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    cmd
}

/// Build a `get_timezones` request.
#[must_use]
pub fn get_timezones() -> impl Request {
    XmlCommand::new("get_timezones")
}

/// Build a legacy system-module `get_aggregates` request.
///
/// New code should use
/// [`crate::commands::aggregates::get_aggregates_request`], which includes the
/// required resource type and models repeated sort and column elements.
#[must_use]
pub fn get_aggregates(opts: GetAggregatesOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_aggregates");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    if let Some(data_column) = opts.data_column.as_deref() {
        cmd.set_attribute("data_column", data_column);
    }
    if let Some(group_column) = opts.group_column.as_deref() {
        cmd.set_attribute("group_column", group_column);
    }
    if let Some(statistic) = opts.statistic {
        cmd.set_attribute("statistic", statistic.as_gmp_str());
    }
    if let Some(sort_field) = opts.sort_field.as_deref() {
        cmd.set_attribute("sort_field", sort_field);
    }
    if let Some(sort_order) = opts.sort_order {
        cmd.set_attribute("sort_order", sort_order.as_gmp_str());
    }
    cmd
}

/// Build a `get_info` request.
#[must_use]
pub fn get_info(opts: GetInfoOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_info");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    if let Some(info_type) = opts.info_type {
        cmd.set_attribute("type", info_type.as_gmp_str());
    }
    if let Some(info_id) = opts.info_id.as_ref() {
        cmd.set_attribute("info_id", info_id.as_str());
    }
    cmd
}

/// Build a `get_preferences` request.
#[must_use]
pub fn get_preferences(opts: FilteredGetOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_preferences");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    cmd
}

/// Build a `get_resource_names` request.
#[must_use]
pub fn get_resource_names(opts: GetResourceNamesOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_resource_names");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    if let Some(resource_type) = opts.resource_type {
        cmd.set_attribute("type", resource_type.as_gmp_str());
    }
    if let Some(resource_id) = opts.resource_id.as_ref() {
        cmd.set_attribute("resource_id", resource_id.as_str());
    }
    cmd
}

/// Build a `get_resource_names` request for a single resource.
#[must_use]
pub fn get_resource_name(resource_id: &EntityId, resource_type: ResourceType) -> impl Request {
    let mut cmd = XmlCommand::new("get_resource_names");
    cmd.set_attribute("resource_id", resource_id.as_str());
    cmd.set_attribute("type", resource_type.as_gmp_str());
    cmd
}

/// Build a `get_vulns` request.
#[must_use]
pub fn get_vulns(opts: FilteredGetOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_vulns");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    cmd
}

/// Build a `get_vulns` request for a single vulnerability entry.
#[must_use]
pub fn get_vuln(vuln_id: &str) -> impl Request {
    XmlCommand::new("get_vulns").attribute("vuln_id", vuln_id)
}

/// Build a `get_vulns` request using python-gvm's descriptive helper name.
#[must_use]
pub fn get_vulnerability(vulnerability_id: &str) -> impl Request {
    get_vuln(vulnerability_id)
}

/// Build a `get_license` request.
#[must_use]
pub fn get_license() -> impl Request {
    XmlCommand::new("get_license")
}

/// Build a `describe_auth` request.
#[must_use]
pub fn describe_auth() -> impl Request {
    XmlCommand::new("describe_auth")
}

/// Build a `modify_auth` request for a named authentication group.
///
/// `auth_conf_settings` must contain at least one key/value pair. Current gvmd
/// accepts a group containing authentication configuration settings; the old
/// `enabled` root attribute is not part of the command contract.
#[must_use]
pub fn modify_auth(group_name: &str, auth_conf_settings: &[(String, String)]) -> impl Request {
    let mut cmd = XmlCommand::new("modify_auth");
    let group = cmd.add_element("group");
    group.set_attribute("name", group_name);
    for (key, value) in auth_conf_settings {
        let setting = group.add_child("auth_conf_setting");
        setting.add_child_with_text("key", key);
        setting.add_child_with_text("value", value);
    }
    cmd
}

/// Build a `modify_license` request with a base64-encoded license file.
#[must_use]
pub fn modify_license(file: &str) -> impl Request {
    modify_license_with_opts(file, ModifyLicenseOpts::default())
}

/// Build a `modify_license` request with explicit options.
#[must_use]
pub fn modify_license_with_opts(file: &str, opts: ModifyLicenseOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_license");
    if let Some(allow_empty) = opts.allow_empty {
        cmd.set_attribute("allow_empty", if allow_empty { "1" } else { "0" });
    }
    cmd.add_element_with_text("file", file);
    cmd
}

/// Build a `modify_setting` request, Base64-encoding the UTF-8 value for GMP.
#[must_use]
pub fn modify_setting(setting_id: &EntityId, value: &str) -> impl Request {
    modify_user_setting(
        setting_id,
        ModifyUserSettingOpts {
            value: value.to_string(),
        },
    )
}

/// Build a `run_wizard` request.
#[must_use]
pub fn run_wizard(name: &str, params: &[(String, String)]) -> impl Request {
    run_wizard_with_opts(name, params, RunWizardOpts::default())
}

/// Build a `run_wizard` request with explicit execution options.
#[must_use]
pub fn run_wizard_with_opts(
    name: &str,
    params: &[(String, String)],
    opts: RunWizardOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("run_wizard");
    if let Some(read_only) = opts.read_only {
        cmd.set_attribute("read_only", if read_only { "1" } else { "0" });
    }
    if let Some(mode) = opts.mode.as_deref() {
        cmd.add_element_with_text("mode", mode);
    }
    cmd.add_element_with_text("name", name);
    let params_element = cmd.add_element("params");
    for (key, value) in params {
        let param = params_element.add_child("param");
        param.add_child_with_text("name", key);
        param.add_child_with_text("value", value);
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn system_commands_build_xml() {
        assert_eq!(xml(help(Some(HelpFormat::Xml))), "<help format=\"xml\"/>");
        assert_eq!(
            xml(get_feeds(GetFeedsOpts {
                feed_type: Some(FeedType::Nvt)
            })),
            "<get_feeds type=\"NVT\"/>"
        );
        let rendered = xml(get_aggregates(GetAggregatesOpts {
            data_column: Some("severity".into()),
            statistic: Some(AggregateStatistic::Count),
            sort_order: Some(SortOrder::Descending),
            ..Default::default()
        }));
        assert!(rendered.contains("data_column=\"severity\""));
        assert!(rendered.contains("statistic=\"count\""));
        assert_eq!(xml(get_license()), "<get_license/>");
        assert_eq!(xml(describe_auth()), "<describe_auth/>");
        assert_eq!(xml(get_timezones()), "<get_timezones/>");
    }

    #[test]
    fn system_filtered_mutation_commands_build_xml() {
        assert!(xml(get_settings(FilteredGetOpts {
            filter_id: Some(id("f1")),
            ..Default::default()
        }))
        .contains("filt_id=\"f1\""));
        assert!(xml(get_system_reports(GetSystemReportsOpts {
            name: Some("load".into()),
            ..Default::default()
        }))
        .contains("name=\"load\""));
        assert!(xml(get_info(GetInfoOpts {
            info_type: Some(InfoType::Nvt),
            info_id: Some(id("i1")),
            ..Default::default()
        }))
        .contains("type=\"NVT\""));
        assert!(xml(get_resource_names(GetResourceNamesOpts {
            resource_type: Some(ResourceType::Task),
            resource_id: Some(id("t1")),
            ..Default::default()
        }))
        .contains("resource_id=\"t1\""));
        assert_eq!(
            xml(get_vulns(FilteredGetOpts {
                filter_string: Some("severity>5".into()),
                filter_id: Some(id("filter-1")),
            })),
            "<get_vulns filt_id=\"filter-1\" filter=\"severity&gt;5\"/>"
        );
        assert_eq!(xml(get_vuln("vuln-1")), "<get_vulns vuln_id=\"vuln-1\"/>");
        assert_eq!(
            xml(get_vulnerability("vuln-1")),
            "<get_vulns vuln_id=\"vuln-1\"/>"
        );
        assert_eq!(
            xml(modify_auth(
                "method:ldap_connect",
                &[("enable".into(), "true".into())]
            )),
            "<modify_auth><group name=\"method:ldap_connect\"><auth_conf_setting><key>enable</key><value>true</value></auth_conf_setting></group></modify_auth>"
        );
        assert_eq!(
            xml(modify_license("abc")),
            "<modify_license><file>abc</file></modify_license>"
        );
        assert_eq!(
            xml(modify_license_with_opts(
                "",
                ModifyLicenseOpts {
                    allow_empty: Some(true)
                }
            )),
            "<modify_license allow_empty=\"1\"><file></file></modify_license>"
        );
        assert_eq!(
            xml(modify_setting(&id("s1"), "Europe/Berlin")),
            "<modify_setting setting_id=\"s1\"><value>RXVyb3BlL0Jlcmxpbg==</value></modify_setting>"
        );
        assert_eq!(
            xml(run_wizard(
                "quick",
                &[("target".into(), "10.0.0.1".into())]
            )),
            "<run_wizard><name>quick</name><params><param><name>target</name><value>10.0.0.1</value></param></params></run_wizard>"
        );
        assert_eq!(
            xml(run_wizard_with_opts(
                "quick",
                &[],
                RunWizardOpts {
                    mode: Some("step".into()),
                    read_only: Some(true),
                }
            )),
            "<run_wizard read_only=\"1\"><mode>step</mode><name>quick</name><params/></run_wizard>"
        );
    }
}
