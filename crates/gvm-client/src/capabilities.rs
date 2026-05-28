// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! gvmd/GMP capability discovery helpers.

use std::collections::BTreeMap;

use gvm_gmp::types::GmpVersion;

/// A typed snapshot of backend capability facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GvmdCapabilitySnapshot {
    /// Negotiated backend descriptor metadata.
    pub backend: GvmdBackendDescriptor,
    /// Capability facts keyed by protocol-oriented identifiers.
    pub capabilities: BTreeMap<GvmdCapability, CapabilitySupport>,
}

/// Low-level backend descriptor facts discovered during negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GvmdBackendDescriptor {
    /// gvmd application version when the backend exposes it.
    pub gvmd_version: Option<String>,
    /// Negotiated GMP version.
    pub gmp_version: Option<GmpVersion>,
    /// Backend product name when the backend exposes it.
    pub product_name: Option<String>,
}

/// Typed capability identifiers kept close to GMP/gvmd concepts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum GvmdCapability {
    /// Command-oriented capability such as `get_features`.
    Command(CommandKind),
    /// Semantic backend fact such as a named feature flag.
    Semantic(SemanticKind),
}

/// Command-level capability identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommandKind {
    /// `get_features`
    GetFeatures,
    /// `create_report_config`
    CreateReportConfig,
    /// `delete_report_config`
    DeleteReportConfig,
    /// `get_report_configs`
    GetReportConfigs,
    /// `modify_report_config`
    ModifyReportConfig,
    /// `get_integration_config`
    GetIntegrationConfig,
    /// `get_integration_configs`
    GetIntegrationConfigs,
    /// `modify_integration_config`
    ModifyIntegrationConfig,
    /// `get_report_hosts`
    GetReportHosts,
    /// `get_report_ports`
    GetReportPorts,
    /// `get_report_applications`
    GetReportApplications,
    /// `get_report_operating_systems`
    GetReportOperatingSystems,
    /// `get_report_cves`
    GetReportCves,
}

/// Semantic or feature-like backend facts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SemanticKind {
    /// A raw named feature reported by `get_features`.
    BackendFeature(String),
}

/// Capability support state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportState {
    /// The capability is supported.
    Supported,
    /// The capability is unsupported.
    Unsupported,
    /// The capability could not be determined conclusively.
    Unknown,
    /// The capability is only partially supported at protocol level.
    Partial,
}

/// Evidence used to infer a capability state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityEvidence {
    /// Determined by issuing a specific probe request.
    ExplicitProbe,
    /// Determined from the response body of `get_features`.
    FeatureCommand,
    /// Determined from the centralized version fallback table.
    VersionTable,
    /// Determined from a static or built-in fixture fact.
    StaticFixture,
}

/// Support status plus evidence metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitySupport {
    /// Support state for the capability.
    pub state: SupportState,
    /// Evidence source used to infer the state.
    pub source: CapabilityEvidence,
    /// Optional explanatory detail such as a version threshold or probe outcome.
    pub detail: Option<String>,
}

impl CapabilitySupport {
    /// Create a support record with explicit state and evidence.
    #[must_use]
    pub fn new(state: SupportState, source: CapabilityEvidence) -> Self {
        Self {
            state,
            source,
            detail: None,
        }
    }

    /// Attach an explanatory detail string.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Build a pure capability snapshot from negotiated GMP version facts.
#[must_use]
pub fn capability_snapshot_for_version(version: GmpVersion) -> GvmdCapabilitySnapshot {
    let mut capabilities = BTreeMap::new();
    for capability in versioned_capabilities() {
        let support = minimum_version_for_capability(capability).map_or(
            CapabilitySupport::new(SupportState::Supported, CapabilityEvidence::StaticFixture),
            |minimum| {
                let state = if version >= minimum {
                    SupportState::Supported
                } else {
                    SupportState::Unsupported
                };
                CapabilitySupport::new(state, CapabilityEvidence::VersionTable)
                    .with_detail(format!("requires GMP >= {}.{}", minimum.0, minimum.1))
            },
        );
        capabilities.insert(capability.clone(), support);
    }

    GvmdCapabilitySnapshot {
        backend: GvmdBackendDescriptor {
            gvmd_version: None,
            gmp_version: Some(version),
            product_name: None,
        },
        capabilities,
    }
}

/// Minimum GMP version required for a command-level capability, when version-gated.
#[must_use]
pub fn minimum_version_for_command(command_name: &str) -> Option<GmpVersion> {
    command_capability(command_name)
        .and_then(|capability| minimum_version_for_capability(&capability))
}

/// Return whether a command is supported by the negotiated version.
#[must_use]
pub fn command_supported(command_name: &str, version: GmpVersion) -> bool {
    match minimum_version_for_command(command_name) {
        Some(minimum) => version >= minimum,
        None => true,
    }
}

/// Human-readable minimum version label for a version-gated command.
#[must_use]
pub fn required_version_label(command_name: &str) -> Option<&'static str> {
    match minimum_version_for_command(command_name) {
        Some(GmpVersion(22, 6)) => Some("22.6"),
        Some(GmpVersion(22, 8)) => Some("22.8"),
        Some(_) | None => None,
    }
}

#[must_use]
pub(crate) fn command_capability(command_name: &str) -> Option<GvmdCapability> {
    Some(GvmdCapability::Command(match command_name {
        "get_features" => CommandKind::GetFeatures,
        "create_report_config" => CommandKind::CreateReportConfig,
        "delete_report_config" => CommandKind::DeleteReportConfig,
        "get_report_configs" => CommandKind::GetReportConfigs,
        "modify_report_config" => CommandKind::ModifyReportConfig,
        "get_integration_config" => CommandKind::GetIntegrationConfig,
        "get_integration_configs" => CommandKind::GetIntegrationConfigs,
        "modify_integration_config" => CommandKind::ModifyIntegrationConfig,
        "get_report_hosts" => CommandKind::GetReportHosts,
        "get_report_ports" => CommandKind::GetReportPorts,
        "get_report_applications" => CommandKind::GetReportApplications,
        "get_report_operating_systems" => CommandKind::GetReportOperatingSystems,
        "get_report_cves" => CommandKind::GetReportCves,
        _ => return None,
    }))
}

#[must_use]
pub(crate) fn minimum_version_for_capability(capability: &GvmdCapability) -> Option<GmpVersion> {
    match capability {
        GvmdCapability::Command(
            CommandKind::CreateReportConfig
            | CommandKind::DeleteReportConfig
            | CommandKind::GetReportConfigs
            | CommandKind::ModifyReportConfig
            | CommandKind::GetFeatures,
        ) => Some(GmpVersion(22, 6)),
        GvmdCapability::Command(
            CommandKind::GetIntegrationConfig
            | CommandKind::GetIntegrationConfigs
            | CommandKind::ModifyIntegrationConfig
            | CommandKind::GetReportHosts
            | CommandKind::GetReportPorts
            | CommandKind::GetReportApplications
            | CommandKind::GetReportOperatingSystems
            | CommandKind::GetReportCves,
        ) => Some(GmpVersion(22, 8)),
        GvmdCapability::Semantic(_) => None,
    }
}

fn versioned_capabilities() -> &'static [GvmdCapability] {
    const CAPABILITIES: &[GvmdCapability] = &[
        GvmdCapability::Command(CommandKind::GetFeatures),
        GvmdCapability::Command(CommandKind::CreateReportConfig),
        GvmdCapability::Command(CommandKind::DeleteReportConfig),
        GvmdCapability::Command(CommandKind::GetReportConfigs),
        GvmdCapability::Command(CommandKind::ModifyReportConfig),
        GvmdCapability::Command(CommandKind::GetIntegrationConfig),
        GvmdCapability::Command(CommandKind::GetIntegrationConfigs),
        GvmdCapability::Command(CommandKind::ModifyIntegrationConfig),
        GvmdCapability::Command(CommandKind::GetReportHosts),
        GvmdCapability::Command(CommandKind::GetReportPorts),
        GvmdCapability::Command(CommandKind::GetReportApplications),
        GvmdCapability::Command(CommandKind::GetReportOperatingSystems),
        GvmdCapability::Command(CommandKind::GetReportCves),
    ];

    CAPABILITIES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_snapshot_marks_unsupported_capabilities() {
        let snapshot = capability_snapshot_for_version(GmpVersion(22, 5));

        assert_eq!(
            snapshot
                .capabilities
                .get(&GvmdCapability::Command(CommandKind::GetFeatures))
                .expect("get_features capability"),
            &CapabilitySupport::new(SupportState::Unsupported, CapabilityEvidence::VersionTable)
                .with_detail("requires GMP >= 22.6")
        );
    }

    #[test]
    fn version_snapshot_marks_newer_commands_supported() {
        let snapshot = capability_snapshot_for_version(GmpVersion(22, 8));

        assert_eq!(
            snapshot
                .capabilities
                .get(&GvmdCapability::Command(CommandKind::GetReportHosts))
                .expect("get_report_hosts capability"),
            &CapabilitySupport::new(SupportState::Supported, CapabilityEvidence::VersionTable)
                .with_detail("requires GMP >= 22.8")
        );
    }

    #[test]
    fn command_mapping_reuses_capability_table() {
        assert_eq!(
            minimum_version_for_command("get_report_cves"),
            Some(GmpVersion(22, 8))
        );
        assert!(command_supported("get_features", GmpVersion(22, 6)));
        assert!(!command_supported("get_features", GmpVersion(22, 5)));
    }
}
