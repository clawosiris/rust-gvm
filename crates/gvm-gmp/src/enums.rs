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
            Self::UpdatedSecInfo => "Updated SecInfo",
            Self::NewSecInfo => "New SecInfo",
        }
    }
}

impl FromStr for AlertEvent {
    type Err = EnumParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "task_run_status_changed" | "Task run status changed" => Ok(Self::TaskRunStatusChanged),
            "updated_secinfo" | "Updated SecInfo" | "Updated Secinfo" => Ok(Self::UpdatedSecInfo),
            "new_secinfo" | "New SecInfo" | "New Secinfo" => Ok(Self::NewSecInfo),
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
            Self::SendEmail => "Send Email",
            Self::Smb => "SMB",
            Self::Snmp => "SNMP",
            Self::SourcefireConnector => "Sourcefire Connector",
            Self::StartTask => "Start Task",
            Self::SysLog => "SysLog",
            Self::TippingPoint => "TippingPoint",
            Self::VeriniceCe => "Verinice CE",
            Self::VeriniceNet => "Verinice Net",
            Self::Alemba => "Alemba",
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
            "send_email" | "Send Email" | "SendEmail" => Ok(Self::SendEmail),
            "smb" | "SMB" => Ok(Self::Smb),
            "snmp" | "SNMP" => Ok(Self::Snmp),
            "sourcefire_connector" | "Sourcefire Connector" => Ok(Self::SourcefireConnector),
            "start_task" | "Start Task" => Ok(Self::StartTask),
            "syslog" | "SysLog" | "Syslog" => Ok(Self::SysLog),
            "tippingpoint" | "TippingPoint" => Ok(Self::TippingPoint),
            "verinice_ce" | "Verinice CE" => Ok(Self::VeriniceCe),
            "verinice_net" | "Verinice Net" => Ok(Self::VeriniceNet),
            "alemba" | "Alemba" => Ok(Self::Alemba),
            _ => Err(EnumParseError {
                enum_name: "AlertMethod",
                value: s.to_string(),
            }),
        }
    }
}

gmp_enum!(AliveTest {
    ScanConfigDefault => "Scan Config Default",
    IcmpPing => "ICMP Ping",
    TcpAckServicePing => "TCP-ACK Service Ping",
    TcpSynServicePing => "TCP-SYN Service Ping",
    ArpPing => "ARP Ping",
    IcmpAndTcpAckServicePing => "ICMP, TCP-ACK Service Ping",
    IcmpAndArpPing => "ICMP, ARP Ping",
    TcpAckServiceAndArpPing => "TCP-ACK Service, ARP Ping",
    IcmpTcpAckServiceAndArpPing => "ICMP, TCP-ACK Service, ARP Ping",
    ConsiderAlive => "Consider Alive"
});
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
gmp_enum!(CredentialType {
    ClientCertificate => "cc",
    PasswordOnly => "pw",
    SnmpV1Or2c => "snmp",
    SnmpV3 => "snmpv3",
    UsernamePassword => "up",
    UsernameSshKey => "usk"
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
gmp_enum!(PortRangeType {
    Tcp => "tcp",
    Udp => "udp"
});
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
gmp_enum!(ScannerType {
    OpenVasScanner => "OpenVAS",
    CveScannerType => "CVE",
    GreenBoneSensorType => "OSP"
});
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
gmp_enum!(TicketStatus {
    Open => "open",
    Fixed => "fixed",
    Closed => "closed"
});
gmp_enum!(UserAuthType {
    File => "file",
    LdapConnect => "ldap_connect",
    RadiusConnect => "radius_connect"
});

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    macro_rules! enum_round_trip_test {
        ($test_name:ident, $ty:ident, $variant:ident, $wire:literal) => {
            #[test]
            fn $test_name() {
                assert_eq!($ty::$variant.as_gmp_str(), $wire);
                assert_eq!($ty::from_str($wire).expect("parse enum"), $ty::$variant);
                assert!($ty::from_str("garbage").is_err());
            }
        };
    }

    enum_round_trip_test!(
        alert_event_round_trip,
        AlertEvent,
        TaskRunStatusChanged,
        "task_run_status_changed"
    );
    enum_round_trip_test!(alert_condition_round_trip, AlertCondition, Always, "always");
    enum_round_trip_test!(alert_method_round_trip, AlertMethod, Email, "email");
    enum_round_trip_test!(
        alive_test_round_trip,
        AliveTest,
        ConsiderAlive,
        "Consider Alive"
    );
    enum_round_trip_test!(
        aggregate_statistic_round_trip,
        AggregateStatistic,
        Count,
        "count"
    );
    enum_round_trip_test!(credential_format_round_trip, CredentialFormat, Pem, "pem");
    enum_round_trip_test!(
        credential_type_round_trip,
        CredentialType,
        UsernamePassword,
        "up"
    );
    enum_round_trip_test!(entity_type_round_trip, EntityType, Task, "task");
    enum_round_trip_test!(feed_type_round_trip, FeedType, Nvt, "NVT");
    enum_round_trip_test!(filter_type_round_trip, FilterType, Task, "task");
    enum_round_trip_test!(help_format_round_trip, HelpFormat, Xml, "xml");
    enum_round_trip_test!(
        hosts_ordering_round_trip,
        HostsOrdering,
        Sequential,
        "sequential"
    );
    enum_round_trip_test!(info_type_round_trip, InfoType, Nvt, "NVT");
    enum_round_trip_test!(
        permission_subject_type_round_trip,
        PermissionSubjectType,
        Role,
        "role"
    );
    enum_round_trip_test!(port_range_type_round_trip, PortRangeType, Tcp, "tcp");
    enum_round_trip_test!(report_format_type_round_trip, ReportFormatType, Pdf, "pdf");
    enum_round_trip_test!(
        scanner_type_round_trip,
        ScannerType,
        OpenVasScanner,
        "OpenVAS"
    );
    enum_round_trip_test!(
        snmp_auth_algorithm_round_trip,
        SnmpAuthAlgorithm,
        Sha1,
        "sha1"
    );
    enum_round_trip_test!(
        snmp_privacy_algorithm_round_trip,
        SnmpPrivacyAlgorithm,
        Aes,
        "aes"
    );
    enum_round_trip_test!(sort_order_round_trip, SortOrder, Ascending, "ascending");
    enum_round_trip_test!(severity_level_round_trip, SeverityLevel, High, "high");
    enum_round_trip_test!(ticket_status_round_trip, TicketStatus, Open, "open");
    enum_round_trip_test!(user_auth_type_round_trip, UserAuthType, File, "file");
}
