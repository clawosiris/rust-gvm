// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! SecInfo command builders.

use gvm_protocol::XmlCommand;

use crate::common::set_optional_bool_attr;

/// Typed `SecInfo` resource kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InfoType {
    /// CERT-Bund advisories.
    CertBundAdvisory,
    /// CPE entries.
    Cpe,
    /// CVE entries.
    Cve,
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
            Self::CertBundAdvisory => "CERT_BUND_ADV",
            Self::Cpe => "CPE",
            Self::Cve => "CVE",
            Self::DfnCertAdvisory => "DFN_CERT_ADV",
            Self::OperatingSystem => "os",
            Self::Vulnerability => "vuln",
        }
    }
}

/// Security information kinds accepted by generic `get_info` requests.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GenericInfoType {
    /// CERT-Bund advisories.
    CertBundAdvisory,
    /// CPE entries.
    Cpe,
    /// CVE entries.
    Cve,
    /// DFN-CERT advisories.
    DfnCertAdvisory,
    /// NVT entries.
    Nvt,
    /// OVAL definition entries.
    Ovaldef,
    /// Operating-system entries.
    OperatingSystem,
    /// Vulnerability entries.
    Vulnerability,
}

impl GenericInfoType {
    /// Returns the GMP wire-format string for this value.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::CertBundAdvisory => "CERT_BUND_ADV",
            Self::Cpe => "CPE",
            Self::Cve => "CVE",
            Self::DfnCertAdvisory => "DFN_CERT_ADV",
            Self::Nvt => "NVT",
            Self::Ovaldef => "OVALDEF",
            Self::OperatingSystem => "os",
            Self::Vulnerability => "vuln",
        }
    }
}

impl From<InfoType> for GenericInfoType {
    fn from(info_type: InfoType) -> Self {
        match info_type {
            InfoType::CertBundAdvisory => Self::CertBundAdvisory,
            InfoType::Cpe => Self::Cpe,
            InfoType::Cve => Self::Cve,
            InfoType::DfnCertAdvisory => Self::DfnCertAdvisory,
            InfoType::OperatingSystem => Self::OperatingSystem,
            InfoType::Vulnerability => Self::Vulnerability,
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

/// Options for generic `get_info` list requests.
#[derive(Debug, Clone, Default)]
pub struct GetInfoListOpts {
    /// Optional inline filter expression.
    pub filter: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Optional name or identifier of the requested information.
    pub name: Option<String>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

impl From<GetSecInfoOpts> for GetInfoListOpts {
    fn from(opts: GetSecInfoOpts) -> Self {
        Self {
            filter: opts.filter,
            filter_id: opts.filter_id,
            name: None,
            details: opts.details,
        }
    }
}

fn build_get_info_list(info_type: GenericInfoType, opts: &GetInfoListOpts) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_info");
    cmd.set_attribute("type", info_type.as_gmp_str());
    if let Some(filter) = opts.filter.as_deref() {
        cmd.set_attribute("filter", filter);
    }
    if let Some(filter_id) = opts.filter_id.as_deref() {
        cmd.set_attribute("filt_id", filter_id);
    }
    if let Some(name) = opts.name.as_deref() {
        cmd.set_attribute("name", name);
    }
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_info` request for one security information entry.
#[must_use]
pub fn get_info(info_id: &str, info_type: GenericInfoType) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_info");
    cmd.set_attribute("info_id", info_id);
    cmd.set_attribute("type", info_type.as_gmp_str());
    cmd.set_attribute("details", "1");
    cmd
}

/// Build a `get_info` request for security information entries.
#[must_use]
pub fn get_info_list(info_type: GenericInfoType, opts: GetInfoListOpts) -> XmlCommand {
    build_get_info_list(info_type, &opts)
}

/// Build a `get_info` request for CPE entries.
#[must_use]
pub fn get_cpes(opts: GetSecInfoOpts) -> XmlCommand {
    build_get_info_list(InfoType::Cpe.into(), &opts.into())
}

/// Build a `get_info` request for a single CPE entry.
#[must_use]
pub fn get_cpe(cpe_id: &str) -> XmlCommand {
    get_info(cpe_id, InfoType::Cpe.into())
}

/// Build a `get_info` request for CVE entries.
#[must_use]
pub fn get_cves(opts: GetSecInfoOpts) -> XmlCommand {
    build_get_info_list(InfoType::Cve.into(), &opts.into())
}

/// Build a `get_info` request for a single CVE entry.
#[must_use]
pub fn get_cve(cve_id: &str) -> XmlCommand {
    get_info(cve_id, InfoType::Cve.into())
}

/// Build a `get_info` request for CERT-Bund advisories.
#[must_use]
pub fn get_cert_bund_advisories(opts: GetSecInfoOpts) -> XmlCommand {
    build_get_info_list(InfoType::CertBundAdvisory.into(), &opts.into())
}

/// Build a `get_info` request for a single CERT-Bund advisory.
#[must_use]
pub fn get_cert_bund_advisory(cert_id: &str) -> XmlCommand {
    get_info(cert_id, InfoType::CertBundAdvisory.into())
}

/// Build a `get_info` request for DFN-CERT advisories.
#[must_use]
pub fn get_dfn_cert_advisories(opts: GetSecInfoOpts) -> XmlCommand {
    build_get_info_list(InfoType::DfnCertAdvisory.into(), &opts.into())
}

/// Build a `get_info` request for a single DFN-CERT advisory.
#[must_use]
pub fn get_dfn_cert_advisory(cert_id: &str) -> XmlCommand {
    get_info(cert_id, InfoType::DfnCertAdvisory.into())
}

/// Build a `get_info` request for operating-system entries.
#[must_use]
pub fn get_operating_systems(opts: GetSecInfoOpts) -> XmlCommand {
    build_get_info_list(InfoType::OperatingSystem.into(), &opts.into())
}

/// Build a `get_info` request for vulnerability entries.
#[must_use]
pub fn get_vulnerabilities(opts: GetSecInfoOpts) -> XmlCommand {
    build_get_info_list(InfoType::Vulnerability.into(), &opts.into())
}

#[cfg(test)]
mod tests {
    use crate::commands::secinfo::{
        get_cert_bund_advisories, get_cert_bund_advisory, get_cpe, get_cpes, get_cve, get_cves,
        get_dfn_cert_advisories, get_dfn_cert_advisory, get_info, get_info_list,
        get_operating_systems, get_vulnerabilities, GenericInfoType, GetInfoListOpts,
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
    fn generic_info_type_variants_map_to_wire_values() {
        assert_eq!(GenericInfoType::Cpe.as_gmp_str(), "CPE");
        assert_eq!(GenericInfoType::Cve.as_gmp_str(), "CVE");
        assert_eq!(
            GenericInfoType::CertBundAdvisory.as_gmp_str(),
            "CERT_BUND_ADV"
        );
        assert_eq!(
            GenericInfoType::DfnCertAdvisory.as_gmp_str(),
            "DFN_CERT_ADV"
        );
        assert_eq!(GenericInfoType::Nvt.as_gmp_str(), "NVT");
        assert_eq!(GenericInfoType::Ovaldef.as_gmp_str(), "OVALDEF");
        assert_eq!(GenericInfoType::OperatingSystem.as_gmp_str(), "os");
        assert_eq!(GenericInfoType::Vulnerability.as_gmp_str(), "vuln");
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

    #[test]
    fn generic_secinfo_compatibility_commands_build_xml() {
        assert_eq!(
            xml(get_info("1.3.6.1.4.1.25623.1", GenericInfoType::Nvt)),
            "<get_info details=\"1\" info_id=\"1.3.6.1.4.1.25623.1\" type=\"NVT\"/>"
        );
        assert_eq!(
            xml(get_info("oval:org.example:def:1", GenericInfoType::Ovaldef)),
            "<get_info details=\"1\" info_id=\"oval:org.example:def:1\" type=\"OVALDEF\"/>"
        );
        assert_eq!(
            xml(get_info_list(
                GenericInfoType::Nvt,
                GetInfoListOpts {
                    filter: Some("family=General".into()),
                    filter_id: Some("filter-1".into()),
                    name: None,
                    details: Some(false),
                },
            )),
            "<get_info details=\"0\" filt_id=\"filter-1\" filter=\"family=General\" type=\"NVT\"/>"
        );
        assert_eq!(
            xml(get_info_list(
                GenericInfoType::Nvt,
                GetInfoListOpts {
                    filter: Some("family=General".into()),
                    filter_id: Some("filter-1".into()),
                    name: Some("Mock NVT one".into()),
                    details: Some(false),
                },
            )),
            "<get_info details=\"0\" filt_id=\"filter-1\" filter=\"family=General\" name=\"Mock NVT one\" type=\"NVT\"/>"
        );
        assert_eq!(
            xml(get_info_list(
                GenericInfoType::Ovaldef,
                GetInfoListOpts::default()
            )),
            "<get_info type=\"OVALDEF\"/>"
        );
    }
}
