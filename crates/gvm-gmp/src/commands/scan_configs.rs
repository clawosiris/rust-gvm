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
use crate::responses::{
    CreateScanConfigResponse, DeleteScanConfigResponse, GetScanConfigPreferencesResponse,
    GetScanConfigsResponse, ModifyScanConfigResponse, ParseError, SyncConfigResponse,
};
use crate::types::EntityId;
use crate::GmpRequest;

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

/// Semantic request for listing scan configurations.
#[derive(Debug, Clone, Default)]
pub struct GetScanConfigsRequest {
    opts: GetScanConfigsOpts,
}

impl GetScanConfigsRequest {
    /// Create a scan-configuration list request.
    #[must_use]
    pub fn new(opts: GetScanConfigsOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetScanConfigsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_scan_configs(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetScanConfigsRequest {
    type Response = GetScanConfigsResponse;
}

/// Semantic request for one detailed scan configuration.
#[derive(Debug, Clone)]
pub struct GetScanConfigRequest {
    config_id: EntityId,
}

impl GetScanConfigRequest {
    /// Create a detailed single scan-configuration request.
    #[must_use]
    pub fn new(config_id: EntityId) -> Self {
        Self { config_id }
    }
}

impl Request for GetScanConfigRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_scan_config(&self.config_id).to_bytes()
    }
}

impl GmpRequest for GetScanConfigRequest {
    type Response = GetScanConfigsResponse;
}

/// Semantic request for creating a scan configuration.
#[derive(Debug, Clone)]
pub struct CreateScanConfigRequest {
    name: String,
    base_id: Option<EntityId>,
    opts: ConfigOpts,
}

impl CreateScanConfigRequest {
    /// Create a scan-configuration creation request.
    #[must_use]
    pub fn new(name: impl Into<String>, base_id: Option<EntityId>, opts: ConfigOpts) -> Self {
        Self {
            name: name.into(),
            base_id,
            opts,
        }
    }
}

impl Request for CreateScanConfigRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_scan_config(&self.name, self.base_id.as_ref(), self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for CreateScanConfigRequest {
    type Response = CreateScanConfigResponse;
}

/// Semantic request for cloning a scan configuration.
#[derive(Debug, Clone)]
pub struct CloneScanConfigRequest {
    config_id: EntityId,
}

impl CloneScanConfigRequest {
    /// Create a scan-configuration clone request.
    #[must_use]
    pub fn new(config_id: EntityId) -> Self {
        Self { config_id }
    }
}

impl Request for CloneScanConfigRequest {
    fn to_bytes(&self) -> Vec<u8> {
        clone_scan_config(&self.config_id).to_bytes()
    }
}

impl GmpRequest for CloneScanConfigRequest {
    type Response = CreateScanConfigResponse;
}

/// Semantic request for importing scan-configuration XML.
#[derive(Debug, Clone)]
pub struct ImportScanConfigRequest {
    bytes: Vec<u8>,
}

impl ImportScanConfigRequest {
    /// Validate import XML and create a scan-configuration import request.
    ///
    /// # Errors
    /// Returns an error under the same conditions as [`import_scan_config`].
    pub fn new(scan_config_xml: &str) -> Result<Self, ParseError> {
        Ok(Self {
            bytes: import_scan_config(scan_config_xml)?.to_bytes(),
        })
    }
}

impl Request for ImportScanConfigRequest {
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl GmpRequest for ImportScanConfigRequest {
    type Response = CreateScanConfigResponse;
}

/// Semantic request for modifying a scan configuration.
#[derive(Debug, Clone)]
pub struct ModifyScanConfigRequest {
    config_id: EntityId,
    opts: ConfigOpts,
}

impl ModifyScanConfigRequest {
    /// Create a scan-configuration modification request.
    #[must_use]
    pub fn new(config_id: EntityId, opts: ConfigOpts) -> Self {
        Self { config_id, opts }
    }
}

impl Request for ModifyScanConfigRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_scan_config(&self.config_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyScanConfigRequest {
    type Response = ModifyScanConfigResponse;
}

/// Semantic request for deleting a scan configuration.
#[derive(Debug, Clone)]
pub struct DeleteScanConfigRequest {
    config_id: EntityId,
    ultimate: bool,
}

impl DeleteScanConfigRequest {
    /// Create a scan-configuration deletion request.
    #[must_use]
    pub fn new(config_id: EntityId, ultimate: bool) -> Self {
        Self {
            config_id,
            ultimate,
        }
    }
}

impl Request for DeleteScanConfigRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_scan_config(&self.config_id, self.ultimate).to_bytes()
    }
}

impl GmpRequest for DeleteScanConfigRequest {
    type Response = DeleteScanConfigResponse;
}

/// Semantic request for globally synchronizing configurations.
#[derive(Debug, Clone, Copy, Default)]
pub struct SyncConfigRequest;

impl SyncConfigRequest {
    /// Create a global configuration synchronization request.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Request for SyncConfigRequest {
    fn to_bytes(&self) -> Vec<u8> {
        sync_config().to_bytes()
    }
}

impl GmpRequest for SyncConfigRequest {
    type Response = SyncConfigResponse;
}

/// Semantic request for listing policies.
#[derive(Debug, Clone, Default)]
pub struct GetPoliciesRequest {
    opts: GetScanConfigsOpts,
}

impl GetPoliciesRequest {
    /// Create a policy list request.
    #[must_use]
    pub fn new(opts: GetScanConfigsOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetPoliciesRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_policies(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetPoliciesRequest {
    type Response = GetScanConfigsResponse;
}

/// Semantic request for one detailed policy.
#[derive(Debug, Clone)]
pub struct GetPolicyRequest {
    policy_id: EntityId,
    opts: GetPolicyOpts,
}

impl GetPolicyRequest {
    /// Create a detailed single-policy request.
    #[must_use]
    pub fn new(policy_id: EntityId, opts: GetPolicyOpts) -> Self {
        Self { policy_id, opts }
    }
}

impl Request for GetPolicyRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_policy(&self.policy_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetPolicyRequest {
    type Response = GetScanConfigsResponse;
}

/// Semantic request for creating a policy.
#[derive(Debug, Clone)]
pub struct CreatePolicyRequest {
    name: String,
    opts: ConfigOpts,
}

impl CreatePolicyRequest {
    /// Create a policy creation request.
    #[must_use]
    pub fn new(name: impl Into<String>, opts: ConfigOpts) -> Self {
        Self {
            name: name.into(),
            opts,
        }
    }
}

impl Request for CreatePolicyRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_policy(&self.name, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for CreatePolicyRequest {
    type Response = CreateScanConfigResponse;
}

/// Semantic request for cloning a policy.
#[derive(Debug, Clone)]
pub struct ClonePolicyRequest {
    policy_id: EntityId,
}

impl ClonePolicyRequest {
    /// Create a policy clone request.
    #[must_use]
    pub fn new(policy_id: EntityId) -> Self {
        Self { policy_id }
    }
}

impl Request for ClonePolicyRequest {
    fn to_bytes(&self) -> Vec<u8> {
        clone_policy(&self.policy_id).to_bytes()
    }
}

impl GmpRequest for ClonePolicyRequest {
    type Response = CreateScanConfigResponse;
}

/// Semantic request for importing policy XML.
#[derive(Debug, Clone)]
pub struct ImportPolicyRequest {
    bytes: Vec<u8>,
}

impl ImportPolicyRequest {
    /// Validate import XML and create a policy import request.
    ///
    /// # Errors
    /// Returns an error under the same conditions as [`import_policy`].
    pub fn new(policy_xml: &str) -> Result<Self, ParseError> {
        Ok(Self {
            bytes: import_policy(policy_xml)?.to_bytes(),
        })
    }
}

impl Request for ImportPolicyRequest {
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl GmpRequest for ImportPolicyRequest {
    type Response = CreateScanConfigResponse;
}

/// Semantic request for modifying a policy.
#[derive(Debug, Clone)]
pub struct ModifyPolicyRequest {
    policy_id: EntityId,
    opts: ConfigOpts,
}

impl ModifyPolicyRequest {
    /// Create a policy modification request.
    #[must_use]
    pub fn new(policy_id: EntityId, opts: ConfigOpts) -> Self {
        Self { policy_id, opts }
    }
}

impl Request for ModifyPolicyRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_policy(&self.policy_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyPolicyRequest {
    type Response = ModifyScanConfigResponse;
}

/// Semantic request for deleting a policy.
#[derive(Debug, Clone)]
pub struct DeletePolicyRequest {
    policy_id: EntityId,
}

impl DeletePolicyRequest {
    /// Create a policy deletion request.
    #[must_use]
    pub fn new(policy_id: EntityId) -> Self {
        Self { policy_id }
    }
}

impl Request for DeletePolicyRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_policy(&self.policy_id).to_bytes()
    }
}

impl GmpRequest for DeletePolicyRequest {
    type Response = DeleteScanConfigResponse;
}

/// Semantic request for scan-configuration preferences.
#[derive(Debug, Clone, Default)]
pub struct GetScanConfigPreferencesRequest {
    opts: GetScanConfigPreferencesOpts,
}

impl GetScanConfigPreferencesRequest {
    /// Create a scan-configuration preference list request.
    #[must_use]
    pub fn new(opts: GetScanConfigPreferencesOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetScanConfigPreferencesRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_scan_config_preferences(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetScanConfigPreferencesRequest {
    type Response = GetScanConfigPreferencesResponse;
}

/// Semantic request for one scan-configuration preference.
#[derive(Debug, Clone)]
pub struct GetScanConfigPreferenceRequest {
    name: String,
    opts: GetScanConfigPreferencesOpts,
}

impl GetScanConfigPreferenceRequest {
    /// Create a single scan-configuration preference request.
    #[must_use]
    pub fn new(name: impl Into<String>, opts: GetScanConfigPreferencesOpts) -> Self {
        Self {
            name: name.into(),
            opts,
        }
    }
}

impl Request for GetScanConfigPreferenceRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_scan_config_preference(&self.name, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetScanConfigPreferenceRequest {
    type Response = GetScanConfigPreferencesResponse;
}

macro_rules! define_nvt_preference_request {
    ($request:ident, $builder:ident, $request_doc:literal, $new_doc:literal) => {
        #[doc = $request_doc]
        #[derive(Debug, Clone)]
        pub struct $request {
            resource_id: EntityId,
            name: String,
            nvt_oid: String,
            value: Option<String>,
        }

        impl $request {
            #[doc = $new_doc]
            #[must_use]
            pub fn new(
                resource_id: EntityId,
                name: impl Into<String>,
                nvt_oid: impl Into<String>,
                value: Option<String>,
            ) -> Self {
                Self {
                    resource_id,
                    name: name.into(),
                    nvt_oid: nvt_oid.into(),
                    value,
                }
            }
        }

        impl Request for $request {
            fn to_bytes(&self) -> Vec<u8> {
                $builder(
                    &self.resource_id,
                    &self.name,
                    &self.nvt_oid,
                    self.value.as_deref(),
                )
                .to_bytes()
            }
        }

        impl GmpRequest for $request {
            type Response = ModifyScanConfigResponse;
        }
    };
}

macro_rules! define_scanner_preference_request {
    ($request:ident, $builder:ident, $request_doc:literal, $new_doc:literal) => {
        #[doc = $request_doc]
        #[derive(Debug, Clone)]
        pub struct $request {
            resource_id: EntityId,
            name: String,
            value: Option<String>,
        }

        impl $request {
            #[doc = $new_doc]
            #[must_use]
            pub fn new(
                resource_id: EntityId,
                name: impl Into<String>,
                value: Option<String>,
            ) -> Self {
                Self {
                    resource_id,
                    name: name.into(),
                    value,
                }
            }
        }

        impl Request for $request {
            fn to_bytes(&self) -> Vec<u8> {
                $builder(&self.resource_id, &self.name, self.value.as_deref()).to_bytes()
            }
        }

        impl GmpRequest for $request {
            type Response = ModifyScanConfigResponse;
        }
    };
}

macro_rules! define_nvt_selection_request {
    ($request:ident, $builder:ident, $request_doc:literal, $new_doc:literal) => {
        #[doc = $request_doc]
        #[derive(Debug, Clone)]
        pub struct $request {
            resource_id: EntityId,
            family: String,
            nvt_oids: Vec<String>,
        }

        impl $request {
            #[doc = $new_doc]
            #[must_use]
            pub fn new(
                resource_id: EntityId,
                family: impl Into<String>,
                nvt_oids: Vec<String>,
            ) -> Self {
                Self {
                    resource_id,
                    family: family.into(),
                    nvt_oids,
                }
            }
        }

        impl Request for $request {
            fn to_bytes(&self) -> Vec<u8> {
                $builder(&self.resource_id, &self.family, &self.nvt_oids).to_bytes()
            }
        }

        impl GmpRequest for $request {
            type Response = ModifyScanConfigResponse;
        }
    };
}

macro_rules! define_family_selection_request {
    ($request:ident, $builder:ident, $request_doc:literal, $new_doc:literal) => {
        #[doc = $request_doc]
        #[derive(Debug, Clone)]
        pub struct $request {
            resource_id: EntityId,
            families: Vec<NvtFamilySelection>,
            auto_add_new_families: bool,
        }

        impl $request {
            #[doc = $new_doc]
            #[must_use]
            pub fn new(
                resource_id: EntityId,
                families: Vec<NvtFamilySelection>,
                auto_add_new_families: bool,
            ) -> Self {
                Self {
                    resource_id,
                    families,
                    auto_add_new_families,
                }
            }
        }

        impl Request for $request {
            fn to_bytes(&self) -> Vec<u8> {
                $builder(
                    &self.resource_id,
                    &self.families,
                    self.auto_add_new_families,
                )
                .to_bytes()
            }
        }

        impl GmpRequest for $request {
            type Response = ModifyScanConfigResponse;
        }
    };
}

macro_rules! define_name_request {
    ($request:ident, $builder:ident, $request_doc:literal, $new_doc:literal) => {
        #[doc = $request_doc]
        #[derive(Debug, Clone)]
        pub struct $request {
            resource_id: EntityId,
            name: String,
        }

        impl $request {
            #[doc = $new_doc]
            #[must_use]
            pub fn new(resource_id: EntityId, name: impl Into<String>) -> Self {
                Self {
                    resource_id,
                    name: name.into(),
                }
            }
        }

        impl Request for $request {
            fn to_bytes(&self) -> Vec<u8> {
                $builder(&self.resource_id, &self.name).to_bytes()
            }
        }

        impl GmpRequest for $request {
            type Response = ModifyScanConfigResponse;
        }
    };
}

macro_rules! define_comment_request {
    ($request:ident, $builder:ident, $request_doc:literal, $new_doc:literal) => {
        #[doc = $request_doc]
        #[derive(Debug, Clone)]
        pub struct $request {
            resource_id: EntityId,
            comment: Option<String>,
        }

        impl $request {
            #[doc = $new_doc]
            #[must_use]
            pub fn new(resource_id: EntityId, comment: Option<String>) -> Self {
                Self {
                    resource_id,
                    comment,
                }
            }
        }

        impl Request for $request {
            fn to_bytes(&self) -> Vec<u8> {
                $builder(&self.resource_id, self.comment.as_deref()).to_bytes()
            }
        }

        impl GmpRequest for $request {
            type Response = ModifyScanConfigResponse;
        }
    };
}

define_nvt_preference_request!(
    ModifyScanConfigSetNvtPreferenceRequest,
    modify_scan_config_set_nvt_preference,
    "Semantic request for setting or deleting a scan-config NVT preference.",
    "Create a scan-config NVT-preference mutation request."
);
define_scanner_preference_request!(
    ModifyScanConfigSetScannerPreferenceRequest,
    modify_scan_config_set_scanner_preference,
    "Semantic request for setting or deleting a scan-config scanner preference.",
    "Create a scan-config scanner-preference mutation request."
);
define_nvt_selection_request!(
    ModifyScanConfigSetNvtSelectionRequest,
    modify_scan_config_set_nvt_selection,
    "Semantic request for replacing a scan-config NVT selection.",
    "Create a scan-config NVT-selection mutation request."
);
define_family_selection_request!(
    ModifyScanConfigSetFamilySelectionRequest,
    modify_scan_config_set_family_selection,
    "Semantic request for replacing a scan-config family selection.",
    "Create a scan-config family-selection mutation request."
);
define_name_request!(
    ModifyScanConfigSetNameRequest,
    modify_scan_config_set_name,
    "Semantic request for setting a scan-configuration name.",
    "Create a scan-configuration name mutation request."
);
define_comment_request!(
    ModifyScanConfigSetCommentRequest,
    modify_scan_config_set_comment,
    "Semantic request for setting or clearing a scan-configuration comment.",
    "Create a scan-configuration comment mutation request."
);

define_nvt_preference_request!(
    ModifyPolicySetNvtPreferenceRequest,
    modify_policy_set_nvt_preference,
    "Semantic request for setting or deleting a policy NVT preference.",
    "Create a policy NVT-preference mutation request."
);
define_scanner_preference_request!(
    ModifyPolicySetScannerPreferenceRequest,
    modify_policy_set_scanner_preference,
    "Semantic request for setting or deleting a policy scanner preference.",
    "Create a policy scanner-preference mutation request."
);
define_nvt_selection_request!(
    ModifyPolicySetNvtSelectionRequest,
    modify_policy_set_nvt_selection,
    "Semantic request for replacing a policy NVT selection.",
    "Create a policy NVT-selection mutation request."
);
define_family_selection_request!(
    ModifyPolicySetFamilySelectionRequest,
    modify_policy_set_family_selection,
    "Semantic request for replacing a policy family selection.",
    "Create a policy family-selection mutation request."
);
define_name_request!(
    ModifyPolicySetNameRequest,
    modify_policy_set_name,
    "Semantic request for setting a policy name.",
    "Create a policy name mutation request."
);
define_comment_request!(
    ModifyPolicySetCommentRequest,
    modify_policy_set_comment,
    "Semantic request for setting or clearing a policy comment.",
    "Create a policy comment mutation request."
);

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

    #[test]
    fn semantic_scan_config_and_policy_requests_match_builders() {
        let config_id = id("config-1");
        let base_id = id("base-1");
        let list_opts = GetScanConfigsOpts {
            filter_string: Some("name=example".into()),
            details: Some(true),
            ..Default::default()
        };
        let config_opts = ConfigOpts {
            comment: Some("comment".into()),
            usage_type: Some("custom".into()),
        };
        let policy_opts = GetPolicyOpts { audits: Some(true) };
        let import_xml = "<get_configs_response><config id=\"config-1\"/></get_configs_response>";

        assert_eq!(
            GetScanConfigsRequest::new(list_opts.clone()).to_bytes(),
            get_scan_configs(list_opts.clone()).to_bytes()
        );
        assert_eq!(
            GetScanConfigRequest::new(config_id.clone()).to_bytes(),
            get_scan_config(&config_id).to_bytes()
        );
        assert_eq!(
            CreateScanConfigRequest::new("config", Some(base_id.clone()), config_opts.clone())
                .to_bytes(),
            create_scan_config("config", Some(&base_id), config_opts.clone()).to_bytes()
        );
        assert_eq!(
            CloneScanConfigRequest::new(config_id.clone()).to_bytes(),
            clone_scan_config(&config_id).to_bytes()
        );
        assert_eq!(
            ImportScanConfigRequest::new(import_xml)
                .expect("valid import")
                .to_bytes(),
            import_scan_config(import_xml)
                .expect("valid import")
                .to_bytes()
        );
        assert_eq!(
            ModifyScanConfigRequest::new(config_id.clone(), config_opts.clone()).to_bytes(),
            modify_scan_config(&config_id, config_opts.clone()).to_bytes()
        );
        assert_eq!(
            DeleteScanConfigRequest::new(config_id.clone(), true).to_bytes(),
            delete_scan_config(&config_id, true).to_bytes()
        );
        assert_eq!(
            SyncConfigRequest::new().to_bytes(),
            sync_config().to_bytes()
        );

        assert_eq!(
            GetPoliciesRequest::new(list_opts.clone()).to_bytes(),
            get_policies(list_opts).to_bytes()
        );
        assert_eq!(
            GetPolicyRequest::new(config_id.clone(), policy_opts.clone()).to_bytes(),
            get_policy(&config_id, policy_opts).to_bytes()
        );
        assert_eq!(
            CreatePolicyRequest::new("policy", config_opts.clone()).to_bytes(),
            create_policy("policy", config_opts.clone()).to_bytes()
        );
        assert_eq!(
            ClonePolicyRequest::new(config_id.clone()).to_bytes(),
            clone_policy(&config_id).to_bytes()
        );
        assert_eq!(
            ImportPolicyRequest::new(import_xml)
                .expect("valid import")
                .to_bytes(),
            import_policy(import_xml).expect("valid import").to_bytes()
        );
        assert_eq!(
            ModifyPolicyRequest::new(config_id.clone(), config_opts.clone()).to_bytes(),
            modify_policy(&config_id, config_opts).to_bytes()
        );
        assert_eq!(
            DeletePolicyRequest::new(config_id.clone()).to_bytes(),
            delete_policy(&config_id).to_bytes()
        );

        assert!(ImportScanConfigRequest::new("<invalid/>").is_err());
        assert!(ImportPolicyRequest::new("<invalid/>").is_err());
    }

    #[test]
    fn semantic_preference_and_selection_requests_match_builders() {
        let resource_id = id("config-1");
        let preference_opts = GetScanConfigPreferencesOpts {
            nvt_oid: Some("1.3.6.1".into()),
            config_id: Some(resource_id.clone()),
        };
        let nvt_oids = vec!["1.3.6.1".into(), "1.3.6.2".into()];
        let families = vec![NvtFamilySelection {
            name: "General".into(),
            growing: true,
            all: false,
        }];

        assert_eq!(
            GetScanConfigPreferencesRequest::new(preference_opts.clone()).to_bytes(),
            get_scan_config_preferences(preference_opts.clone()).to_bytes()
        );
        assert_eq!(
            GetScanConfigPreferenceRequest::new("timeout", preference_opts.clone()).to_bytes(),
            get_scan_config_preference("timeout", preference_opts).to_bytes()
        );

        assert_eq!(
            ModifyScanConfigSetNvtPreferenceRequest::new(
                resource_id.clone(),
                "timeout",
                "1.3.6.1",
                Some("30".into())
            )
            .to_bytes(),
            modify_scan_config_set_nvt_preference(&resource_id, "timeout", "1.3.6.1", Some("30"))
                .to_bytes()
        );
        assert_eq!(
            ModifyScanConfigSetScannerPreferenceRequest::new(
                resource_id.clone(),
                "max_checks",
                None
            )
            .to_bytes(),
            modify_scan_config_set_scanner_preference(&resource_id, "max_checks", None).to_bytes()
        );
        assert_eq!(
            ModifyScanConfigSetNvtSelectionRequest::new(
                resource_id.clone(),
                "General",
                nvt_oids.clone()
            )
            .to_bytes(),
            modify_scan_config_set_nvt_selection(&resource_id, "General", &nvt_oids).to_bytes()
        );
        assert_eq!(
            ModifyScanConfigSetFamilySelectionRequest::new(
                resource_id.clone(),
                families.clone(),
                true
            )
            .to_bytes(),
            modify_scan_config_set_family_selection(&resource_id, &families, true).to_bytes()
        );
        assert_eq!(
            ModifyScanConfigSetNameRequest::new(resource_id.clone(), "renamed").to_bytes(),
            modify_scan_config_set_name(&resource_id, "renamed").to_bytes()
        );
        assert_eq!(
            ModifyScanConfigSetCommentRequest::new(resource_id.clone(), None).to_bytes(),
            modify_scan_config_set_comment(&resource_id, None).to_bytes()
        );
    }

    #[test]
    fn semantic_policy_preference_and_selection_requests_match_builders() {
        let resource_id = id("policy-1");
        let nvt_oids = vec!["1.3.6.1".into(), "1.3.6.2".into()];
        let families = vec![NvtFamilySelection {
            name: "General".into(),
            growing: true,
            all: false,
        }];

        assert_eq!(
            ModifyPolicySetNvtPreferenceRequest::new(
                resource_id.clone(),
                "timeout",
                "1.3.6.1",
                Some("30".into())
            )
            .to_bytes(),
            modify_policy_set_nvt_preference(&resource_id, "timeout", "1.3.6.1", Some("30"))
                .to_bytes()
        );
        assert_eq!(
            ModifyPolicySetScannerPreferenceRequest::new(resource_id.clone(), "max_checks", None)
                .to_bytes(),
            modify_policy_set_scanner_preference(&resource_id, "max_checks", None).to_bytes()
        );
        assert_eq!(
            ModifyPolicySetNvtSelectionRequest::new(
                resource_id.clone(),
                "General",
                nvt_oids.clone()
            )
            .to_bytes(),
            modify_policy_set_nvt_selection(&resource_id, "General", &nvt_oids).to_bytes()
        );
        assert_eq!(
            ModifyPolicySetFamilySelectionRequest::new(
                resource_id.clone(),
                families.clone(),
                false
            )
            .to_bytes(),
            modify_policy_set_family_selection(&resource_id, &families, false).to_bytes()
        );
        assert_eq!(
            ModifyPolicySetNameRequest::new(resource_id.clone(), "renamed").to_bytes(),
            modify_policy_set_name(&resource_id, "renamed").to_bytes()
        );
        assert_eq!(
            ModifyPolicySetCommentRequest::new(resource_id.clone(), Some("comment".into()))
                .to_bytes(),
            modify_policy_set_comment(&resource_id, Some("comment")).to_bytes()
        );
    }

    #[test]
    fn semantic_scan_config_requests_have_expected_response_associations() {
        fn assert_response<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: crate::GmpResponse,
        {
        }

        let resource_id = id("config-1");
        assert_response::<_, GetScanConfigsResponse>(&GetScanConfigsRequest::default());
        assert_response::<_, GetScanConfigsResponse>(&GetScanConfigRequest::new(
            resource_id.clone(),
        ));
        assert_response::<_, CreateScanConfigResponse>(&CreateScanConfigRequest::new(
            "config",
            None,
            ConfigOpts::default(),
        ));
        assert_response::<_, CreateScanConfigResponse>(&CloneScanConfigRequest::new(
            resource_id.clone(),
        ));
        assert_response::<_, CreateScanConfigResponse>(
            &ImportScanConfigRequest::new("<get_configs_response/>").expect("valid import"),
        );
        assert_response::<_, ModifyScanConfigResponse>(&ModifyScanConfigRequest::new(
            resource_id.clone(),
            ConfigOpts::default(),
        ));
        assert_response::<_, DeleteScanConfigResponse>(&DeleteScanConfigRequest::new(
            resource_id.clone(),
            false,
        ));
        assert_response::<_, SyncConfigResponse>(&SyncConfigRequest::new());
        assert_response::<_, GetScanConfigPreferencesResponse>(
            &GetScanConfigPreferencesRequest::default(),
        );
        assert_response::<_, GetScanConfigPreferencesResponse>(
            &GetScanConfigPreferenceRequest::new(
                "timeout",
                GetScanConfigPreferencesOpts::default(),
            ),
        );
        assert_response::<_, GetScanConfigsResponse>(&GetPoliciesRequest::default());
        assert_response::<_, GetScanConfigsResponse>(&GetPolicyRequest::new(
            resource_id.clone(),
            GetPolicyOpts::default(),
        ));
        assert_response::<_, CreateScanConfigResponse>(&CreatePolicyRequest::new(
            "policy",
            ConfigOpts::default(),
        ));
        assert_response::<_, CreateScanConfigResponse>(&ClonePolicyRequest::new(
            resource_id.clone(),
        ));
        assert_response::<_, CreateScanConfigResponse>(
            &ImportPolicyRequest::new("<get_configs_response/>").expect("valid import"),
        );
        assert_response::<_, ModifyScanConfigResponse>(&ModifyPolicyRequest::new(
            resource_id.clone(),
            ConfigOpts::default(),
        ));
        assert_response::<_, DeleteScanConfigResponse>(&DeletePolicyRequest::new(resource_id));
    }
}
