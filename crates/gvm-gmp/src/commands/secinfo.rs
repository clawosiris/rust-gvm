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
            Self::Cpe => "CPE",
            Self::Cve => "CVE",
            Self::CertBundAdvisory => "CERT_BUND_ADV",
            Self::DfnCertAdvisory => "DFN_CERT_ADV",
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

fn get_info_by_id(info_type: InfoType, info_id: &str) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_info");
    cmd.set_attribute("info_id", info_id);
    cmd.set_attribute("type", info_type.as_gmp_str());
    cmd.set_attribute("details", "1");
    cmd
}

/// Build a `get_info` request for CPE entries.
#[must_use]
pub fn get_cpes(opts: GetSecInfoOpts) -> XmlCommand {
    get_info(InfoType::Cpe.as_gmp_str(), &opts)
}

/// Build a `get_info` request for a single CPE entry.
#[must_use]
pub fn get_cpe(cpe_id: &str) -> XmlCommand {
    get_info_by_id(InfoType::Cpe, cpe_id)
}

/// Build a `get_info` request for CVE entries.
#[must_use]
pub fn get_cves(opts: GetSecInfoOpts) -> XmlCommand {
    get_info(InfoType::Cve.as_gmp_str(), &opts)
}

/// Build a `get_info` request for a single CVE entry.
#[must_use]
pub fn get_cve(cve_id: &str) -> XmlCommand {
    get_info_by_id(InfoType::Cve, cve_id)
}

/// Build a `get_info` request for CERT-Bund advisories.
#[must_use]
pub fn get_cert_bund_advisories(opts: GetSecInfoOpts) -> XmlCommand {
    get_info(InfoType::CertBundAdvisory.as_gmp_str(), &opts)
}

/// Build a `get_info` request for a single CERT-Bund advisory.
#[must_use]
pub fn get_cert_bund_advisory(cert_id: &str) -> XmlCommand {
    get_info_by_id(InfoType::CertBundAdvisory, cert_id)
}

/// Build a `get_info` request for DFN-CERT advisories.
#[must_use]
pub fn get_dfn_cert_advisories(opts: GetSecInfoOpts) -> XmlCommand {
    get_info(InfoType::DfnCertAdvisory.as_gmp_str(), &opts)
}

/// Build a `get_info` request for a single DFN-CERT advisory.
#[must_use]
pub fn get_dfn_cert_advisory(cert_id: &str) -> XmlCommand {
    get_info_by_id(InfoType::DfnCertAdvisory, cert_id)
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
        get_cert_bund_advisories, get_cert_bund_advisory, get_cpe, get_cpes, get_cve, get_cves,
        get_dfn_cert_advisories, get_dfn_cert_advisory, get_operating_systems, get_vulnerabilities,
        GetSecInfoOpts, InfoType,
    };
    use crate::common::xml;

    #[test]
    fn info_type_variants_map_to_wire_values() {
        assert_eq!(InfoType::Cpe.as_gmp_str(), "CPE");
        assert_eq!(InfoType::Cve.as_gmp_str(), "CVE");
        assert_eq!(InfoType::CertBundAdvisory.as_gmp_str(), "CERT_BUND_ADV");
        assert_eq!(InfoType::DfnCertAdvisory.as_gmp_str(), "DFN_CERT_ADV");
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
            "<get_info details=\"1\" filt_id=\"f1\" filter=\"family=foo\" type=\"CPE\"/>"
        );
        assert_eq!(
            xml(get_cves(GetSecInfoOpts::default())),
            "<get_info type=\"CVE\"/>"
        );
        assert_eq!(
            xml(get_cert_bund_advisories(GetSecInfoOpts::default())),
            "<get_info type=\"CERT_BUND_ADV\"/>"
        );
        assert_eq!(
            xml(get_dfn_cert_advisories(GetSecInfoOpts::default())),
            "<get_info type=\"DFN_CERT_ADV\"/>"
        );
        assert_eq!(
            xml(get_operating_systems(GetSecInfoOpts::default())),
            "<get_info type=\"os\"/>"
        );
        assert_eq!(
            xml(get_vulnerabilities(GetSecInfoOpts::default())),
            "<get_info type=\"vuln\"/>"
        );
        assert_eq!(
            xml(get_cpe("cpe:/a:greenbone:gvm")),
            "<get_info details=\"1\" info_id=\"cpe:/a:greenbone:gvm\" type=\"CPE\"/>"
        );
        assert_eq!(
            xml(get_cve("CVE-2026-1000")),
            "<get_info details=\"1\" info_id=\"CVE-2026-1000\" type=\"CVE\"/>"
        );
        assert_eq!(
            xml(get_cert_bund_advisory("CB-K26/001")),
            "<get_info details=\"1\" info_id=\"CB-K26/001\" type=\"CERT_BUND_ADV\"/>"
        );
        assert_eq!(
            xml(get_dfn_cert_advisory("DFN-2026-001")),
            "<get_info details=\"1\" info_id=\"DFN-2026-001\" type=\"DFN_CERT_ADV\"/>"
        );
    }
}
