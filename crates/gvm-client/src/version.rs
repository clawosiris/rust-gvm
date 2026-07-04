// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! GMP version parsing and negotiation helpers.

use gvm_gmp::types::GmpVersion;

use crate::GvmError;

/// Minimum GMP version required for a command, when version-gated.
#[must_use]
pub fn minimum_version_for_command(command_name: &str) -> Option<GmpVersion> {
    match command_name {
        "create_report_config"
        | "delete_report_config"
        | "get_report_configs"
        | "modify_report_config"
        | "get_features" => Some(GmpVersion(22, 6)),
        "create_agent_group"
        | "delete_agent_group"
        | "get_agent_groups"
        | "modify_agent_group"
        | "get_integration_configs"
        | "modify_integration_config"
        | "get_report_hosts"
        | "get_report_ports"
        | "get_report_applications"
        | "get_report_operating_systems"
        | "get_report_cves"
        | "get_report_vulns"
        | "get_report_tls_certificates"
        | "get_report_errors"
        | "get_report_closed_cves"
        | "get_timezones"
        | "get_report_export"
        | "get_credential_stores"
        | "create_web_application_target"
        | "delete_web_application_target"
        | "get_web_application_targets"
        | "modify_web_application_target" => Some(GmpVersion(22, 8)),
        _ => None,
    }
}

/// Return whether a command is supported by the negotiated version.
#[must_use]
pub fn command_supported(command_name: &str, version: GmpVersion) -> bool {
    minimum_version_for_command(command_name).is_none_or(|minimum| version >= minimum)
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

/// Parse a GMP version string into a major/minor pair.
///
/// Accepts `major.minor` and optional `major.minor.patch` strings.
///
/// # Errors
/// Returns an error if the string does not start with two numeric components.
pub fn parse_version_text(input: &str) -> Result<GmpVersion, GvmError> {
    let value = input.trim();
    let mut parts = value.split('.');

    let major = parse_component(parts.next(), value)?;
    let minor = parse_component(parts.next(), value)?;

    if let Some(patch) = parts.next() {
        let _ = parse_component(Some(patch), value)?;
    }

    Ok(GmpVersion(major, minor))
}

fn parse_component(component: Option<&str>, value: &str) -> Result<u16, GvmError> {
    let parsed = component
        .ok_or_else(|| GvmError::XmlParse(format!("invalid version string: {value}")))?
        .parse::<u16>()
        .map_err(|_| GvmError::XmlParse(format!("invalid version string: {value}")))?;

    if parsed > 99 {
        return Err(GvmError::XmlParse(format!(
            "invalid version string: {value}"
        )));
    }

    Ok(parsed)
}

/// Map a negotiated GMP version into the supported client version set.
///
/// # Errors
/// Returns an error if the major version is unsupported or the minor version is
/// older than the supported range.
pub fn map_supported_version(version: GmpVersion) -> Result<GmpVersion, GvmError> {
    match version {
        GmpVersion(22, 4..=7) => Ok(version),
        GmpVersion(22, minor) if minor > 7 => Ok(version),
        GmpVersion(major, minor) => Err(GvmError::UnsupportedVersion(major, minor)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_major_minor() {
        assert_eq!(
            parse_version_text("22.5").expect("valid"),
            GmpVersion(22, 5)
        );
    }

    #[test]
    fn parses_major_minor_with_patch_suffix() {
        assert_eq!(
            parse_version_text("22.7.1").expect("valid"),
            GmpVersion(22, 7)
        );
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(
            parse_version_text(" 22.6 \n").expect("valid"),
            GmpVersion(22, 6)
        );
    }

    #[test]
    fn rejects_invalid_versions() {
        let error = parse_version_text("22").expect_err("invalid");
        assert!(matches!(error, GvmError::XmlParse(_)));
    }

    #[test]
    fn rejects_malformed_version_strings() {
        for input in ["abc", "999.999.999", "", "70000.1"] {
            assert!(matches!(
                parse_version_text(input).expect_err("invalid"),
                GvmError::XmlParse(_)
            ));
        }
    }

    #[test]
    fn maps_known_supported_versions() {
        assert_eq!(
            map_supported_version(GmpVersion(22, 4)).expect("supported"),
            GmpVersion(22, 4)
        );
        assert_eq!(
            map_supported_version(GmpVersion(22, 7)).expect("supported"),
            GmpVersion(22, 7)
        );
    }

    #[test]
    fn maps_newer_minor_to_next_compatible_version() {
        assert_eq!(
            map_supported_version(GmpVersion(22, 8)).expect("supported"),
            GmpVersion(22, 8)
        );
    }

    #[test]
    fn rejects_unsupported_versions() {
        assert!(matches!(
            map_supported_version(GmpVersion(21, 4)).expect_err("unsupported"),
            GvmError::UnsupportedVersion(21, 4)
        ));
        assert!(matches!(
            map_supported_version(GmpVersion(22, 3)).expect_err("unsupported"),
            GvmError::UnsupportedVersion(22, 3)
        ));
    }

    #[test]
    fn command_support_respects_version_gates() {
        assert!(command_supported("get_tasks", GmpVersion(22, 4)));
        assert!(!command_supported("get_features", GmpVersion(22, 5)));
        assert!(command_supported("get_features", GmpVersion(22, 6)));
        assert!(!command_supported("get_report_hosts", GmpVersion(22, 7)));
        assert!(command_supported("get_report_hosts", GmpVersion(22, 8)));
        assert!(!command_supported("get_report_export", GmpVersion(22, 7)));
        assert!(command_supported("get_report_export", GmpVersion(22, 8)));
        assert_eq!(
            minimum_version_for_command("get_report_cves"),
            Some(GmpVersion(22, 8))
        );
        assert!(!command_supported("get_timezones", GmpVersion(22, 7)));
        assert!(command_supported("get_timezones", GmpVersion(22, 8)));
        assert_eq!(
            minimum_version_for_command("get_report_vulns"),
            Some(GmpVersion(22, 8))
        );
        assert_eq!(
            minimum_version_for_command("get_credential_stores"),
            Some(GmpVersion(22, 8))
        );
        assert!(!command_supported("get_agent_groups", GmpVersion(22, 7)));
        assert!(command_supported("get_agent_groups", GmpVersion(22, 8)));
        assert_eq!(
            minimum_version_for_command("create_agent_group"),
            Some(GmpVersion(22, 8))
        );
        assert!(!command_supported(
            "get_web_application_targets",
            GmpVersion(22, 7)
        ));
        assert!(command_supported(
            "get_web_application_targets",
            GmpVersion(22, 8)
        ));
        assert_eq!(
            minimum_version_for_command("create_web_application_target"),
            Some(GmpVersion(22, 8))
        );
    }
}
