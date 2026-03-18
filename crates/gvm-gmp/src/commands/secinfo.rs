// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! SecInfo command builders.

use gvm_protocol::XmlCommand;

use crate::common::set_optional_bool_attr;

/// Typed `SecInfo` resource kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InfoType {
    /// CPE entries.
    Cpe,
    /// CVE entries.
    Cve,
    /// CERT-Bund advisories.
    CertBundAdvisory,
    /// DFN-CERT advisories.
    DfnCertAdvisory,
    /// Operating-system entries.
    OperatingSystem,
    /// Vulnerability entries.
    Vulnerability,
}

impl InfoType {
    /// Returns the GMP wire-format string for this value.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::Cpe => "cpe",
            Self::Cve => "cve",
            Self::CertBundAdvisory => "cert_bund_adv",
            Self::DfnCertAdvisory => "dfn_cert_adv",
            Self::OperatingSystem => "os",
            Self::Vulnerability => "vuln",
        }
    }
}

/// Options shared by all `SecInfo` getters.
#[derive(Debug, Clone, Default)]
pub struct GetSecInfoOpts {
    /// Optional inline filter expression.
    pub filter: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

fn get_info(info_type: &str, opts: &GetSecInfoOpts) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_info");
    cmd.set_attribute("type", info_type);
    if let Some(filter) = opts.filter.as_deref() {
        cmd.set_attribute("filter", filter);
    }
    if let Some(filter_id) = opts.filter_id.as_deref() {
        cmd.set_attribute("filt_id", filter_id);
    }
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_info` request for CPE entries.
#[must_use]
pub fn get_cpes(opts: GetSecInfoOpts) -> XmlCommand {
    get_info(InfoType::Cpe.as_gmp_str(), &opts)
}

/// Build a `get_info` request for CVE entries.
#[must_use]
pub fn get_cves(opts: GetSecInfoOpts) -> XmlCommand {
    get_info(InfoType::Cve.as_gmp_str(), &opts)
}

/// Build a `get_info` request for CERT-Bund advisories.
#[must_use]
pub fn get_cert_bund_advisories(opts: GetSecInfoOpts) -> XmlCommand {
    get_info(InfoType::CertBundAdvisory.as_gmp_str(), &opts)
}

/// Build a `get_info` request for DFN-CERT advisories.
#[must_use]
pub fn get_dfn_cert_advisories(opts: GetSecInfoOpts) -> XmlCommand {
    get_info(InfoType::DfnCertAdvisory.as_gmp_str(), &opts)
}

/// Build a `get_info` request for operating-system entries.
#[must_use]
pub fn get_operating_systems(opts: GetSecInfoOpts) -> XmlCommand {
    get_info(InfoType::OperatingSystem.as_gmp_str(), &opts)
}

/// Build a `get_info` request for vulnerability entries.
#[must_use]
pub fn get_vulnerabilities(opts: GetSecInfoOpts) -> XmlCommand {
    get_info(InfoType::Vulnerability.as_gmp_str(), &opts)
}

#[cfg(test)]
mod tests {
    use crate::commands::secinfo::{
        get_cert_bund_advisories, get_cpes, get_cves, get_dfn_cert_advisories,
        get_operating_systems, get_vulnerabilities, GetSecInfoOpts, InfoType,
    };
    use crate::common::xml;

    #[test]
    fn info_type_variants_map_to_wire_values() {
        assert_eq!(InfoType::Cpe.as_gmp_str(), "cpe");
        assert_eq!(InfoType::Cve.as_gmp_str(), "cve");
        assert_eq!(InfoType::CertBundAdvisory.as_gmp_str(), "cert_bund_adv");
        assert_eq!(InfoType::DfnCertAdvisory.as_gmp_str(), "dfn_cert_adv");
        assert_eq!(InfoType::OperatingSystem.as_gmp_str(), "os");
        assert_eq!(InfoType::Vulnerability.as_gmp_str(), "vuln");
    }

    #[test]
    fn secinfo_commands_build_xml() {
        let opts = GetSecInfoOpts {
            filter: Some("family=foo".into()),
            filter_id: Some("f1".into()),
            details: Some(true),
        };
        assert_eq!(
            xml(get_cpes(opts.clone())),
            "<get_info details=\"1\" filt_id=\"f1\" filter=\"family=foo\" type=\"cpe\"/>"
        );
        assert_eq!(
            xml(get_cves(GetSecInfoOpts::default())),
            "<get_info type=\"cve\"/>"
        );
        assert_eq!(
            xml(get_cert_bund_advisories(GetSecInfoOpts::default())),
            "<get_info type=\"cert_bund_adv\"/>"
        );
        assert_eq!(
            xml(get_dfn_cert_advisories(GetSecInfoOpts::default())),
            "<get_info type=\"dfn_cert_adv\"/>"
        );
        assert_eq!(
            xml(get_operating_systems(GetSecInfoOpts::default())),
            "<get_info type=\"os\"/>"
        );
        assert_eq!(
            xml(get_vulnerabilities(GetSecInfoOpts::default())),
            "<get_info type=\"vuln\"/>"
        );
    }
}
