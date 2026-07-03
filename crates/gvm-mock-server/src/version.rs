// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! GMP version configuration.

/// Supported GMP versions for the mock server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GmpVersion {
    /// GMP 22.4
    V22_4,
    /// GMP 22.5
    #[default]
    V22_5,
    /// GMP 22.6
    V22_6,
    /// GMP 22.7
    V22_7,
    /// GMP 22.8
    V22_8,
}

impl GmpVersion {
    /// Return the version string as used in GMP responses.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V22_4 => "22.4",
            Self::V22_5 => "22.5",
            Self::V22_6 => "22.6",
            Self::V22_7 => "22.7",
            Self::V22_8 => "22.8",
        }
    }
}

impl std::fmt::Display for GmpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Commands only available in GMP 22.6+.
const GMP_22_6_COMMANDS: &[&str] = &[
    "create_report_config",
    "delete_report_config",
    "get_report_configs",
    "modify_report_config",
    "get_features",
];

/// Commands only available in GMP 22.8+ / GMP Next.
const GMP_22_8_COMMANDS: &[&str] = &[
    "create_agent_group",
    "delete_agent_group",
    "get_agent_groups",
    "get_integration_configs",
    "modify_integration_config",
    "modify_agent_group",
    "get_report_hosts",
    "get_report_ports",
    "get_report_applications",
    "get_report_operating_systems",
    "get_report_cves",
    "get_report_vulns",
    "get_report_tls_certificates",
    "get_report_errors",
    "get_report_closed_cves",
    "get_timezones",
    "get_credential_stores",
];

/// Check if a command is available in the given GMP version.
#[must_use]
pub fn command_available(command_name: &str, version: GmpVersion) -> bool {
    if GMP_22_8_COMMANDS.contains(&command_name) {
        return matches!(version, GmpVersion::V22_8);
    }
    if GMP_22_6_COMMANDS.contains(&command_name) {
        return matches!(
            version,
            GmpVersion::V22_6 | GmpVersion::V22_7 | GmpVersion::V22_8
        );
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_as_str() {
        assert_eq!(GmpVersion::V22_4.as_str(), "22.4");
        assert_eq!(GmpVersion::V22_5.as_str(), "22.5");
        assert_eq!(GmpVersion::V22_6.as_str(), "22.6");
        assert_eq!(GmpVersion::V22_7.as_str(), "22.7");
        assert_eq!(GmpVersion::V22_8.as_str(), "22.8");
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", GmpVersion::V22_4), "22.4");
        assert_eq!(format!("{}", GmpVersion::V22_5), "22.5");
        assert_eq!(format!("{}", GmpVersion::V22_6), "22.6");
        assert_eq!(format!("{}", GmpVersion::V22_7), "22.7");
        assert_eq!(format!("{}", GmpVersion::V22_8), "22.8");
    }

    #[test]
    fn test_default() {
        assert_eq!(GmpVersion::default(), GmpVersion::V22_5);
    }

    #[test]
    fn test_clone_and_eq() {
        let v = GmpVersion::V22_6;
        let v2 = v;
        assert_eq!(v, v2);
    }

    #[test]
    fn test_debug() {
        let s = format!("{:?}", GmpVersion::V22_7);
        assert!(s.contains("V22_7"));
    }

    #[test]
    fn test_command_available_for_base_commands() {
        assert!(command_available("get_version", GmpVersion::V22_4));
        assert!(command_available("authenticate", GmpVersion::V22_5));
        assert!(command_available("create_target", GmpVersion::V22_4));
    }

    #[test]
    fn test_command_available_for_report_config_commands() {
        assert!(!command_available(
            "create_report_config",
            GmpVersion::V22_4
        ));
        assert!(!command_available(
            "create_report_config",
            GmpVersion::V22_5
        ));
        assert!(command_available("create_report_config", GmpVersion::V22_6));
        assert!(command_available("create_report_config", GmpVersion::V22_7));
        assert!(command_available("create_report_config", GmpVersion::V22_8));
        assert!(!command_available(
            "delete_report_config",
            GmpVersion::V22_4
        ));
        assert!(command_available("modify_report_config", GmpVersion::V22_7));
    }

    #[test]
    fn test_command_available_for_get_features() {
        assert!(!command_available("get_features", GmpVersion::V22_5));
        assert!(command_available("get_features", GmpVersion::V22_6));
        assert!(command_available("get_features", GmpVersion::V22_7));
        assert!(command_available("get_features", GmpVersion::V22_8));
    }

    #[test]
    fn test_command_available_for_next_commands() {
        assert!(!command_available(
            "get_integration_configs",
            GmpVersion::V22_7
        ));
        assert!(command_available(
            "get_integration_configs",
            GmpVersion::V22_8
        ));
        assert!(!command_available("get_report_hosts", GmpVersion::V22_6));
        assert!(command_available("get_report_hosts", GmpVersion::V22_8));
        assert!(!command_available("get_report_vulns", GmpVersion::V22_7));
        assert!(command_available("get_report_vulns", GmpVersion::V22_8));
        assert!(command_available(
            "get_credential_stores",
            GmpVersion::V22_8
        ));
        assert!(!command_available("get_agent_groups", GmpVersion::V22_7));
        assert!(command_available("get_agent_groups", GmpVersion::V22_8));
        assert!(!command_available("create_agent_group", GmpVersion::V22_6));
        assert!(command_available("create_agent_group", GmpVersion::V22_8));
    }
}
