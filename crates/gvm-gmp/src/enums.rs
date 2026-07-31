// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! GMP enums and wire-format conversions.

use std::str::FromStr;

macro_rules! gmp_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[doc = concat!("GMP enum values for `", stringify!($name), "`.")]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub enum $name {
            $(#[doc = concat!("Maps to the GMP wire value `", $value, "`.")] $variant),+
        }

        impl $name {
            /// Returns the GMP wire-format string for this value.
            #[must_use]
            pub const fn as_gmp_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value),+
                }
            }
        }

        impl FromStr for $name {
            type Err = EnumParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(EnumParseError {
                        enum_name: stringify!($name),
                        value: s.to_string(),
                    }),
                }
            }
        }
    };
}

/// Error returned when parsing a GMP enum from its wire value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {enum_name} value: {value}")]
pub struct EnumParseError {
    enum_name: &'static str,
    value: String,
}

/// Stable alert event values plus gvmd-compatible display-name aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AlertEvent {
    /// Alert on task run status changes.
    TaskRunStatusChanged,
    /// Alert on updated security information.
    UpdatedSecInfo,
    /// Alert on new security information.
    NewSecInfo,
}

impl AlertEvent {
    /// Returns the stable GMP-facing value used by downstream consumers.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::TaskRunStatusChanged => "task_run_status_changed",
            Self::UpdatedSecInfo => "updated_secinfo",
            Self::NewSecInfo => "new_secinfo",
        }
    }

    /// Returns the gvmd-compatible display name accepted by alert create/modify.
    #[must_use]
    pub const fn as_alert_name(self) -> &'static str {
        match self {
            Self::TaskRunStatusChanged => "Task run status changed",
            Self::UpdatedSecInfo => "Updated SecInfo arrived",
            Self::NewSecInfo => "New SecInfo arrived",
        }
    }
}

impl FromStr for AlertEvent {
    type Err = EnumParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "task_run_status_changed" | "Task run status changed" => Ok(Self::TaskRunStatusChanged),
            "updated_secinfo"
            | "Updated SecInfo arrived"
            | "Updated Secinfo arrived"
            | "Updated SecInfo"
            | "Updated Secinfo" => Ok(Self::UpdatedSecInfo),
            "new_secinfo"
            | "New SecInfo arrived"
            | "New Secinfo arrived"
            | "New SecInfo"
            | "New Secinfo" => Ok(Self::NewSecInfo),
            _ => Err(EnumParseError {
                enum_name: "AlertEvent",
                value: s.to_string(),
            }),
        }
    }
}

/// Stable alert condition values plus gvmd-compatible display-name aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AlertCondition {
    /// Trigger the alert unconditionally.
    Always,
    /// Trigger when the filter count reaches at least a threshold.
    FilterCountAtLeast,
    /// Trigger when the filter count changes.
    FilterCountChanged,
    /// Trigger when severity reaches at least a threshold.
    SeverityAtLeast,
    /// Trigger when severity changes.
    SeverityChanged,
}

impl AlertCondition {
    /// Returns the stable GMP-facing value used by downstream consumers.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::FilterCountAtLeast => "filter_count_at_least",
            Self::FilterCountChanged => "filter_count_changed",
            Self::SeverityAtLeast => "severity_at_least",
            Self::SeverityChanged => "severity_changed",
        }
    }

    /// Returns the gvmd-compatible display name accepted by alert create/modify.
    #[must_use]
    pub const fn as_alert_name(self) -> &'static str {
        match self {
            Self::Always => "Always",
            Self::FilterCountAtLeast => "Filter count at least",
            Self::FilterCountChanged => "Filter count changed",
            Self::SeverityAtLeast => "Severity at least",
            Self::SeverityChanged => "Severity changed",
        }
    }
}

impl FromStr for AlertCondition {
    type Err = EnumParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "always" | "Always" => Ok(Self::Always),
            "filter_count_at_least" | "Filter count at least" => Ok(Self::FilterCountAtLeast),
            "filter_count_changed" | "Filter count changed" => Ok(Self::FilterCountChanged),
            "severity_at_least" | "Severity at least" => Ok(Self::SeverityAtLeast),
            "severity_changed" | "Severity changed" => Ok(Self::SeverityChanged),
            _ => Err(EnumParseError {
                enum_name: "AlertCondition",
                value: s.to_string(),
            }),
        }
    }
}

/// Stable alert method values plus gvmd-compatible display-name aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AlertMethod {
    /// Deliver the alert by email.
    Email,
    /// Deliver the alert with an HTTP GET request.
    HttpGet,
    /// Deliver the alert over SCP.
    Scp,
    /// Deliver the alert with the gvmd Send Email method.
    SendEmail,
    /// Deliver the alert over SMB.
    Smb,
    /// Deliver the alert over SNMP.
    Snmp,
    /// Deliver the alert to a Sourcefire connector.
    SourcefireConnector,
    /// Trigger a task start action.
    StartTask,
    /// Deliver the alert to Syslog.
    SysLog,
    /// Deliver the alert to `TippingPoint`.
    TippingPoint,
    /// Deliver the alert to Verinice CE.
    VeriniceCe,
    /// Deliver the alert to Verinice Net.
    VeriniceNet,
    /// Deliver the alert to Alemba.
    Alemba,
}

impl AlertMethod {
    /// Returns the stable GMP-facing value used by downstream consumers.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::HttpGet => "http_get",
            Self::Scp => "scp",
            Self::SendEmail => "send_email",
            Self::Smb => "smb",
            Self::Snmp => "snmp",
            Self::SourcefireConnector => "sourcefire_connector",
            Self::StartTask => "start_task",
            Self::SysLog => "syslog",
            Self::TippingPoint => "tippingpoint",
            Self::VeriniceCe => "verinice_ce",
            Self::VeriniceNet => "verinice_net",
            Self::Alemba => "alemba",
        }
    }

    /// Returns the gvmd-compatible display name accepted by alert create/modify.
    #[must_use]
    pub const fn as_alert_name(self) -> &'static str {
        match self {
            Self::Email => "Email",
            Self::HttpGet => "HTTP Get",
            Self::Scp => "SCP",
            Self::SendEmail => "Send",
            Self::Smb => "SMB",
            Self::Snmp => "SNMP",
            Self::SourcefireConnector => "Sourcefire Connector",
            Self::StartTask => "Start Task",
            Self::SysLog => "Syslog",
            Self::TippingPoint => "TippingPoint SMS",
            Self::VeriniceCe => "verinice Connector",
            Self::VeriniceNet => "verinice Connector",
            Self::Alemba => "Alemba vFire",
        }
    }
}

impl FromStr for AlertMethod {
    type Err = EnumParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "email" | "Email" => Ok(Self::Email),
            "http_get" | "HTTP Get" | "Http Get" => Ok(Self::HttpGet),
            "scp" | "SCP" => Ok(Self::Scp),
            "send_email" | "Send" | "Send Email" | "SendEmail" => Ok(Self::SendEmail),
            "smb" | "SMB" => Ok(Self::Smb),
            "snmp" | "SNMP" => Ok(Self::Snmp),
            "sourcefire_connector" | "Sourcefire Connector" => Ok(Self::SourcefireConnector),
            "start_task" | "Start Task" => Ok(Self::StartTask),
            "syslog" | "SysLog" | "Syslog" => Ok(Self::SysLog),
            "tippingpoint" | "TippingPoint" | "TippingPoint SMS" => Ok(Self::TippingPoint),
            // gvmd collapses the legacy Verinice variants into one display name.
            "verinice_ce" | "verinice Connector" | "Verinice CE" => Ok(Self::VeriniceCe),
            "verinice_net" | "Verinice Net" => Ok(Self::VeriniceNet),
            "alemba" | "Alemba" | "Alemba vFire" => Ok(Self::Alemba),
            _ => Err(EnumParseError {
                enum_name: "AlertMethod",
                value: s.to_string(),
            }),
        }
    }
}

/// Stable alive-test values plus gvmd/python-gvm 22.7 aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AliveTest {
    ScanConfigDefault,
    IcmpPing,
    TcpAckServicePing,
    TcpSynServicePing,
    ArpPing,
    IcmpAndTcpAckServicePing,
    IcmpAndArpPing,
    TcpAckServiceAndArpPing,
    IcmpTcpAckServiceAndArpPing,
    ConsiderAlive,
}

impl AliveTest {
    /// Returns the stable consumer-facing value retained for backward compatibility.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::ScanConfigDefault => "Scan Config Default",
            Self::IcmpPing => "ICMP Ping",
            Self::TcpAckServicePing => "TCP-ACK Service Ping",
            Self::TcpSynServicePing => "TCP-SYN Service Ping",
            Self::ArpPing => "ARP Ping",
            Self::IcmpAndTcpAckServicePing => "ICMP, TCP-ACK Service Ping",
            Self::IcmpAndArpPing => "ICMP, ARP Ping",
            Self::TcpAckServiceAndArpPing => "TCP-ACK Service, ARP Ping",
            Self::IcmpTcpAckServiceAndArpPing => "ICMP, TCP-ACK Service, ARP Ping",
            Self::ConsiderAlive => "Consider Alive",
        }
    }

    /// Returns the gvmd/python-gvm 22.7 value accepted by target create/modify.
    #[must_use]
    pub const fn as_target_name(self) -> &'static str {
        match self {
            Self::ScanConfigDefault => "Scan Config Default",
            Self::IcmpPing => "ICMP Ping",
            Self::TcpAckServicePing => "TCP-ACK Service Ping",
            Self::TcpSynServicePing => "TCP-SYN Service Ping",
            Self::ArpPing => "ARP Ping",
            Self::IcmpAndTcpAckServicePing => "ICMP & TCP-ACK Service Ping",
            Self::IcmpAndArpPing => "ICMP & ARP Ping",
            Self::TcpAckServiceAndArpPing => "TCP-ACK Service & ARP Ping",
            Self::IcmpTcpAckServiceAndArpPing => "ICMP, TCP-ACK Service & ARP Ping",
            Self::ConsiderAlive => "Consider Alive",
        }
    }
}

impl FromStr for AliveTest {
    type Err = EnumParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Scan Config Default" => Ok(Self::ScanConfigDefault),
            "ICMP Ping" => Ok(Self::IcmpPing),
            "TCP-ACK Service Ping" => Ok(Self::TcpAckServicePing),
            "TCP-SYN Service Ping" => Ok(Self::TcpSynServicePing),
            "ARP Ping" => Ok(Self::ArpPing),
            "ICMP, TCP-ACK Service Ping" | "ICMP & TCP-ACK Service Ping" => {
                Ok(Self::IcmpAndTcpAckServicePing)
            }
            "ICMP, ARP Ping" | "ICMP & ARP Ping" => Ok(Self::IcmpAndArpPing),
            "TCP-ACK Service, ARP Ping" | "TCP-ACK Service & ARP Ping" => {
                Ok(Self::TcpAckServiceAndArpPing)
            }
            "ICMP, TCP-ACK Service, ARP Ping" | "ICMP, TCP-ACK Service & ARP Ping" => {
                Ok(Self::IcmpTcpAckServiceAndArpPing)
            }
            "Consider Alive" => Ok(Self::ConsiderAlive),
            _ => Err(EnumParseError {
                enum_name: "AliveTest",
                value: s.to_string(),
            }),
        }
    }
}
gmp_enum!(AggregateStatistic {
    Count => "count",
    CMax => "c_max",
    CSum => "c_sum",
    Max => "max",
    Mean => "mean",
    Min => "min",
    Sum => "sum",
    Text => "text",
    Value => "value",
    WordCounts => "word_counts"
});
gmp_enum!(CredentialFormat {
    Exe => "exe",
    Pem => "pem",
    Pgp => "pgp",
    Rpm => "rpm"
});
/// Credential types accepted by current gvmd.
///
/// gvmd uses the same `snmp` wire type for community-based and `SNMPv3`
/// credentials; the presence of authentication/privacy fields distinguishes
/// the latter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CredentialType {
    /// Client certificate (`cc`).
    ClientCertificate,
    /// Kerberos 5 (`krb5`).
    Kerberos5,
    /// Password-only credential (`pw`).
    PasswordOnly,
    /// PGP encryption key (`pgp`).
    PgpEncryptionKey,
    /// S/MIME certificate (`smime`).
    SmimeCertificate,
    /// Community-based SNMP credential (`snmp`).
    SnmpV1Or2c,
    /// `SNMPv3` credential (`snmp` with authentication/privacy fields).
    SnmpV3,
    /// Username and password (`up`).
    UsernamePassword,
    /// Username and SSH key (`usk`).
    UsernameSshKey,
}

impl CredentialType {
    /// Returns the GMP wire-format string for this credential type.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::ClientCertificate => "cc",
            Self::Kerberos5 => "krb5",
            Self::PasswordOnly => "pw",
            Self::PgpEncryptionKey => "pgp",
            Self::SmimeCertificate => "smime",
            Self::SnmpV1Or2c | Self::SnmpV3 => "snmp",
            Self::UsernamePassword => "up",
            Self::UsernameSshKey => "usk",
        }
    }
}

impl FromStr for CredentialType {
    type Err = EnumParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cc" => Ok(Self::ClientCertificate),
            "krb5" => Ok(Self::Kerberos5),
            "pw" => Ok(Self::PasswordOnly),
            "pgp" => Ok(Self::PgpEncryptionKey),
            "smime" => Ok(Self::SmimeCertificate),
            "snmp" => Ok(Self::SnmpV1Or2c),
            "snmpv3" => Ok(Self::SnmpV3),
            "up" => Ok(Self::UsernamePassword),
            "usk" => Ok(Self::UsernameSshKey),
            _ => Err(EnumParseError {
                enum_name: "CredentialType",
                value: s.to_string(),
            }),
        }
    }
}
gmp_enum!(CredentialStoreCredentialType {
    ClientCertificate => "cs_cc",
    PasswordOnly => "cs_pw",
    PgpEncryptionKey => "cs_pgp",
    SmimeCertificate => "cs_smime",
    Snmp => "cs_snmp",
    UsernamePassword => "cs_up",
    UsernameSshKey => "cs_usk"
});
gmp_enum!(EntityType {
    Alert => "alert",
    Asset => "asset",
    AuditReport => "audit_report",
    CertBundAdv => "cert_bund_adv",
    Config => "config",
    Cpe => "cpe",
    Credential => "credential",
    Cve => "cve",
    DfnCertAdv => "dfn_cert_adv",
    Filter => "filter",
    Group => "group",
    Host => "host",
    Note => "note",
    Nvt => "nvt",
    OperatingSystem => "operating_system",
    Override => "override",
    Permission => "permission",
    Policy => "policy",
    PortList => "port_list",
    Report => "report",
    ReportConfig => "report_config",
    ReportFormat => "report_format",
    ResourceName => "resource_name",
    Result => "result",
    Role => "role",
    Scanner => "scanner",
    Schedule => "schedule",
    Tag => "tag",
    Target => "target",
    Task => "task",
    Ticket => "ticket",
    TlsCertificate => "tls_certificate",
    User => "user",
    Vulnerability => "vulnerability"
});
/// Resource types accepted by `get_resource_names`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ResourceType {
    /// Alert resources.
    Alert,
    /// Audit resources are represented as tasks in GMP.
    Audit,
    /// Audit report resources are represented as reports in GMP.
    AuditReport,
    /// CERT-Bund advisory resources.
    CertBundAdv,
    /// Scan configuration resources.
    Config,
    /// CPE resources.
    Cpe,
    /// Credential resources.
    Credential,
    /// CVE resources.
    Cve,
    /// DFN-CERT advisory resources.
    DfnCertAdv,
    /// Filter resources.
    Filter,
    /// Group resources.
    Group,
    /// Host resources.
    Host,
    /// Note resources.
    Note,
    /// NVT resources.
    Nvt,
    /// Operating system resources.
    OperatingSystem,
    /// Override resources.
    Override,
    /// Permission resources.
    Permission,
    /// Port list resources.
    PortList,
    /// Report format resources.
    ReportFormat,
    /// Report resources.
    Report,
    /// Report config resources.
    ReportConfig,
    /// Result resources.
    Result,
    /// Role resources.
    Role,
    /// Scanner resources.
    Scanner,
    /// Schedule resources.
    Schedule,
    /// Target resources.
    Target,
    /// Task resources.
    Task,
    /// TLS certificate resources.
    TlsCertificate,
    /// User resources.
    User,
}

impl ResourceType {
    /// Returns the GMP wire-format string for this value.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::Alert => "ALERT",
            Self::Audit | Self::Task => "TASK",
            Self::AuditReport | Self::Report => "REPORT",
            Self::CertBundAdv => "CERT_BUND_ADV",
            Self::Config => "CONFIG",
            Self::Cpe => "CPE",
            Self::Credential => "CREDENTIAL",
            Self::Cve => "CVE",
            Self::DfnCertAdv => "DFN_CERT_ADV",
            Self::Filter => "FILTER",
            Self::Group => "GROUP",
            Self::Host => "HOST",
            Self::Note => "NOTE",
            Self::Nvt => "NVT",
            Self::OperatingSystem => "OS",
            Self::Override => "OVERRIDE",
            Self::Permission => "PERMISSION",
            Self::PortList => "PORT_LIST",
            Self::ReportFormat => "REPORT_FORMAT",
            Self::ReportConfig => "REPORT_CONFIG",
            Self::Result => "RESULT",
            Self::Role => "ROLE",
            Self::Scanner => "SCANNER",
            Self::Schedule => "SCHEDULE",
            Self::Target => "TARGET",
            Self::TlsCertificate => "TLS_CERTIFICATE",
            Self::User => "USER",
        }
    }
}

impl FromStr for ResourceType {
    type Err = EnumParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ALERT" => Ok(Self::Alert),
            "TASK" => Ok(Self::Task),
            "REPORT" => Ok(Self::Report),
            "CERT_BUND_ADV" => Ok(Self::CertBundAdv),
            "CONFIG" => Ok(Self::Config),
            "CPE" => Ok(Self::Cpe),
            "CREDENTIAL" => Ok(Self::Credential),
            "CVE" => Ok(Self::Cve),
            "DFN_CERT_ADV" => Ok(Self::DfnCertAdv),
            "FILTER" => Ok(Self::Filter),
            "GROUP" => Ok(Self::Group),
            "HOST" => Ok(Self::Host),
            "NOTE" => Ok(Self::Note),
            "NVT" => Ok(Self::Nvt),
            "OS" => Ok(Self::OperatingSystem),
            "OVERRIDE" => Ok(Self::Override),
            "PERMISSION" => Ok(Self::Permission),
            "PORT_LIST" => Ok(Self::PortList),
            "REPORT_FORMAT" => Ok(Self::ReportFormat),
            "REPORT_CONFIG" => Ok(Self::ReportConfig),
            "RESULT" => Ok(Self::Result),
            "ROLE" => Ok(Self::Role),
            "SCANNER" => Ok(Self::Scanner),
            "SCHEDULE" => Ok(Self::Schedule),
            "TARGET" => Ok(Self::Target),
            "TLS_CERTIFICATE" => Ok(Self::TlsCertificate),
            "USER" => Ok(Self::User),
            _ => Err(EnumParseError {
                enum_name: "ResourceType",
                value: s.to_string(),
            }),
        }
    }
}
gmp_enum!(FeedType {
    Nvt => "NVT",
    Cert => "CERT",
    Scap => "SCAP",
    Gvmd => "GVMD_DATA"
});
gmp_enum!(FilterType {
    Alert => "alert",
    Asset => "asset",
    Config => "config",
    Credential => "credential",
    Filter => "filter",
    Group => "group",
    Host => "host",
    Note => "note",
    Override => "override",
    Permission => "permission",
    PortList => "port_list",
    Report => "report",
    ReportFormat => "report_format",
    Result => "result",
    Role => "role",
    Scanner => "scanner",
    Schedule => "schedule",
    Setting => "setting",
    Tag => "tag",
    Target => "target",
    Task => "task",
    Ticket => "ticket",
    TlsCertificate => "tls_certificate",
    User => "user",
    Vulnerability => "vulnerability"
});
gmp_enum!(HelpFormat {
    Html => "html",
    Rnc => "rnc",
    Text => "text",
    Xml => "xml"
});
gmp_enum!(HostsOrdering {
    Sequential => "sequential",
    Random => "random",
    Reverse => "reverse"
});
gmp_enum!(InfoType {
    CertBundAdv => "CERT_BUND_ADV",
    Cpe => "CPE",
    Cve => "CVE",
    DfnCertAdv => "DFN_CERT_ADV",
    Nvt => "NVT",
    Ovaldef => "OVALDEF"
});
gmp_enum!(PermissionSubjectType {
    Group => "group",
    Role => "role",
    User => "user"
});
/// Stable port-range values plus gvmd/python-gvm 22.7 aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PortRangeType {
    Tcp,
    Udp,
}

impl PortRangeType {
    /// Returns the stable consumer-facing value retained for backward compatibility.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    /// Returns the gvmd/python-gvm 22.7 value accepted by `create_port_range`.
    #[must_use]
    pub const fn as_port_range_type(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

impl FromStr for PortRangeType {
    type Err = EnumParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" | "TCP" => Ok(Self::Tcp),
            "udp" | "UDP" => Ok(Self::Udp),
            _ => Err(EnumParseError {
                enum_name: "PortRangeType",
                value: s.to_string(),
            }),
        }
    }
}
gmp_enum!(ReportFormatType {
    Anonymous => "anonymous",
    Csv => "csv",
    Itg => "itg",
    LaTexPdf => "latex_pdf",
    Nbr => "nbr",
    Pdf => "pdf",
    Svg => "svg",
    TxtReport => "txt",
    Verinice => "verinice",
    Xml => "xml"
});
/// Stable scanner-type values plus gvmd/python-gvm 22.7 aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ScannerType {
    OpenVasScanner,
    CveScannerType,
    GreenBoneSensorType,
    OpenVasdScannerType,
}

impl ScannerType {
    /// Returns the stable consumer-facing value retained for backward compatibility.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::OpenVasScanner => "OpenVAS",
            Self::CveScannerType => "CVE",
            Self::GreenBoneSensorType => "OSP",
            Self::OpenVasdScannerType => "6",
        }
    }

    /// Returns the gvmd/python-gvm 22.7 value accepted by scanner create/modify.
    #[must_use]
    pub const fn as_scanner_type(self) -> &'static str {
        match self {
            Self::OpenVasScanner => "2",
            Self::CveScannerType => "3",
            Self::GreenBoneSensorType => "5",
            Self::OpenVasdScannerType => "6",
        }
    }
}

impl FromStr for ScannerType {
    type Err = EnumParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "OpenVAS" | "2" => Ok(Self::OpenVasScanner),
            "CVE" | "3" => Ok(Self::CveScannerType),
            "OSP" | "5" => Ok(Self::GreenBoneSensorType),
            "6" => Ok(Self::OpenVasdScannerType),
            _ => Err(EnumParseError {
                enum_name: "ScannerType",
                value: s.to_string(),
            }),
        }
    }
}
gmp_enum!(SnmpAuthAlgorithm {
    Md5 => "md5",
    Sha1 => "sha1"
});
gmp_enum!(SnmpPrivacyAlgorithm {
    Aes => "aes",
    Des => "des"
});
gmp_enum!(SortOrder {
    Ascending => "ascending",
    Descending => "descending"
});
gmp_enum!(SeverityLevel {
    High => "high",
    Medium => "medium",
    Low => "low",
    Log => "log",
    Alarm => "alarm"
});
/// Stable ticket-status values plus gvmd/python-gvm 22.7 aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TicketStatus {
    Open,
    Fixed,
    Closed,
}

impl TicketStatus {
    /// Returns the stable consumer-facing value retained for backward compatibility.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Fixed => "fixed",
            Self::Closed => "closed",
        }
    }

    /// Returns the gvmd/python-gvm 22.7 value accepted by ticket create/modify.
    #[must_use]
    pub const fn as_ticket_status(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Fixed => "Fixed",
            Self::Closed => "Closed",
        }
    }
}

impl FromStr for TicketStatus {
    type Err = EnumParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" | "Open" => Ok(Self::Open),
            "fixed" | "Fixed" => Ok(Self::Fixed),
            "closed" | "Closed" => Ok(Self::Closed),
            _ => Err(EnumParseError {
                enum_name: "TicketStatus",
                value: s.to_string(),
            }),
        }
    }
}
gmp_enum!(UserAuthType {
    File => "file",
    LdapConnect => "ldap_connect",
    RadiusConnect => "radius_connect"
});
