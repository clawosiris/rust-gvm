// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]

use std::fmt::Debug;
use std::str::FromStr;

use gvm_gmp::*;

fn swapped_ascii_case(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_lowercase() {
                character.to_ascii_uppercase()
            } else if character.is_ascii_uppercase() {
                character.to_ascii_lowercase()
            } else {
                character
            }
        })
        .collect()
}

fn assert_strict_rejections<T>(accepted: &[&str])
where
    T: FromStr,
    T::Err: Debug,
{
    assert!("__unknown_enum_value__".parse::<T>().is_err());

    for value in accepted {
        for near_miss in [
            format!(" {value}"),
            format!("{value} "),
            format!("\t{value}"),
            format!("{value}\n"),
        ] {
            assert!(
                near_miss.parse::<T>().is_err(),
                "whitespace near-miss unexpectedly accepted: {near_miss:?}"
            );
        }

        let case_swap = swapped_ascii_case(value);
        if case_swap != *value && !accepted.contains(&case_swap.as_str()) {
            assert!(
                case_swap.parse::<T>().is_err(),
                "case near-miss unexpectedly accepted: {case_swap:?}"
            );
        }
    }
}

macro_rules! canonical_inventory {
    (
        $test_name:ident,
        $type:ident,
        {
            $($variant:ident => ($canonical:literal, $parsed:ident)),+ $(,)?
        },
        aliases {
            $($alias:literal => $alias_variant:ident),* $(,)?
        }
    ) => {
        #[test]
        fn $test_name() {
            fn require_exhaustive_inventory(value: $type) {
                match value {
                    $($type::$variant => {}),+
                }
            }

            let canonical = [
                $(($type::$variant, $canonical, $type::$parsed)),+
            ];
            let aliases = [
                $(($alias, $type::$alias_variant)),*
            ];
            let mut accepted = Vec::with_capacity(canonical.len() + aliases.len());

            for (value, wire, parsed) in canonical {
                require_exhaustive_inventory(value);
                assert_eq!(value.as_gmp_str(), wire);
                assert_eq!(
                    $type::from_str(wire).expect("canonical wire value must parse"),
                    parsed
                );
                accepted.push(wire);
            }
            for (wire, expected) in aliases {
                assert_eq!(
                    $type::from_str(wire).expect("documented alias must parse"),
                    expected
                );
                accepted.push(wire);
            }

            assert_strict_rejections::<$type>(&accepted);
        }
    };
}

macro_rules! secondary_inventory {
    (
        $test_name:ident,
        $type:ident,
        $method:ident,
        {
            $($variant:ident => $wire:literal),+ $(,)?
        }
    ) => {
        #[test]
        fn $test_name() {
            fn require_exhaustive_inventory(value: $type) {
                match value {
                    $($type::$variant => {}),+
                }
            }

            for (value, wire) in [
                $(($type::$variant, $wire)),+
            ] {
                require_exhaustive_inventory(value);
                assert_eq!(value.$method(), wire);
            }
        }
    };
}

canonical_inventory!(
    alert_event_wire_inventory,
    AlertEvent,
    {
        TaskRunStatusChanged => ("task_run_status_changed", TaskRunStatusChanged),
        UpdatedSecInfo => ("updated_secinfo", UpdatedSecInfo),
        NewSecInfo => ("new_secinfo", NewSecInfo),
    },
    aliases {
        "Task run status changed" => TaskRunStatusChanged,
        "Updated SecInfo arrived" => UpdatedSecInfo,
        "Updated Secinfo arrived" => UpdatedSecInfo,
        "Updated SecInfo" => UpdatedSecInfo,
        "Updated Secinfo" => UpdatedSecInfo,
        "New SecInfo arrived" => NewSecInfo,
        "New Secinfo arrived" => NewSecInfo,
        "New SecInfo" => NewSecInfo,
        "New Secinfo" => NewSecInfo,
    }
);

secondary_inventory!(
    alert_event_display_name_inventory,
    AlertEvent,
    as_alert_name,
    {
        TaskRunStatusChanged => "Task run status changed",
        UpdatedSecInfo => "Updated SecInfo arrived",
        NewSecInfo => "New SecInfo arrived",
    }
);

canonical_inventory!(
    alert_condition_wire_inventory,
    AlertCondition,
    {
        Always => ("always", Always),
        FilterCountAtLeast => ("filter_count_at_least", FilterCountAtLeast),
        FilterCountChanged => ("filter_count_changed", FilterCountChanged),
        SeverityAtLeast => ("severity_at_least", SeverityAtLeast),
        SeverityChanged => ("severity_changed", SeverityChanged),
    },
    aliases {
        "Always" => Always,
        "Filter count at least" => FilterCountAtLeast,
        "Filter count changed" => FilterCountChanged,
        "Severity at least" => SeverityAtLeast,
        "Severity changed" => SeverityChanged,
    }
);

secondary_inventory!(
    alert_condition_display_name_inventory,
    AlertCondition,
    as_alert_name,
    {
        Always => "Always",
        FilterCountAtLeast => "Filter count at least",
        FilterCountChanged => "Filter count changed",
        SeverityAtLeast => "Severity at least",
        SeverityChanged => "Severity changed",
    }
);

canonical_inventory!(
    alert_method_wire_inventory,
    AlertMethod,
    {
        Email => ("email", Email),
        HttpGet => ("http_get", HttpGet),
        Scp => ("scp", Scp),
        SendEmail => ("send_email", SendEmail),
        Smb => ("smb", Smb),
        Snmp => ("snmp", Snmp),
        SourcefireConnector => ("sourcefire_connector", SourcefireConnector),
        StartTask => ("start_task", StartTask),
        SysLog => ("syslog", SysLog),
        TippingPoint => ("tippingpoint", TippingPoint),
        VeriniceCe => ("verinice_ce", VeriniceCe),
        VeriniceNet => ("verinice_net", VeriniceNet),
        Alemba => ("alemba", Alemba),
    },
    aliases {
        "Email" => Email,
        "HTTP Get" => HttpGet,
        "Http Get" => HttpGet,
        "SCP" => Scp,
        "Send" => SendEmail,
        "Send Email" => SendEmail,
        "SendEmail" => SendEmail,
        "SMB" => Smb,
        "SNMP" => Snmp,
        "Sourcefire Connector" => SourcefireConnector,
        "Start Task" => StartTask,
        "SysLog" => SysLog,
        "Syslog" => SysLog,
        "TippingPoint" => TippingPoint,
        "TippingPoint SMS" => TippingPoint,
        "verinice Connector" => VeriniceCe,
        "Verinice CE" => VeriniceCe,
        "Verinice Net" => VeriniceNet,
        "Alemba" => Alemba,
        "Alemba vFire" => Alemba,
    }
);

secondary_inventory!(
    alert_method_display_name_inventory,
    AlertMethod,
    as_alert_name,
    {
        Email => "Email",
        HttpGet => "HTTP Get",
        Scp => "SCP",
        SendEmail => "Send",
        Smb => "SMB",
        Snmp => "SNMP",
        SourcefireConnector => "Sourcefire Connector",
        StartTask => "Start Task",
        SysLog => "Syslog",
        TippingPoint => "TippingPoint SMS",
        VeriniceCe => "verinice Connector",
        VeriniceNet => "verinice Connector",
        Alemba => "Alemba vFire",
    }
);

canonical_inventory!(
    alive_test_wire_inventory,
    AliveTest,
    {
        ScanConfigDefault => ("Scan Config Default", ScanConfigDefault),
        IcmpPing => ("ICMP Ping", IcmpPing),
        TcpAckServicePing => ("TCP-ACK Service Ping", TcpAckServicePing),
        TcpSynServicePing => ("TCP-SYN Service Ping", TcpSynServicePing),
        ArpPing => ("ARP Ping", ArpPing),
        IcmpAndTcpAckServicePing => ("ICMP, TCP-ACK Service Ping", IcmpAndTcpAckServicePing),
        IcmpAndArpPing => ("ICMP, ARP Ping", IcmpAndArpPing),
        TcpAckServiceAndArpPing => ("TCP-ACK Service, ARP Ping", TcpAckServiceAndArpPing),
        IcmpTcpAckServiceAndArpPing => (
            "ICMP, TCP-ACK Service, ARP Ping",
            IcmpTcpAckServiceAndArpPing
        ),
        ConsiderAlive => ("Consider Alive", ConsiderAlive),
    },
    aliases {
        "ICMP & TCP-ACK Service Ping" => IcmpAndTcpAckServicePing,
        "ICMP & ARP Ping" => IcmpAndArpPing,
        "TCP-ACK Service & ARP Ping" => TcpAckServiceAndArpPing,
        "ICMP, TCP-ACK Service & ARP Ping" => IcmpTcpAckServiceAndArpPing,
    }
);

secondary_inventory!(
    alive_test_target_name_inventory,
    AliveTest,
    as_target_name,
    {
        ScanConfigDefault => "Scan Config Default",
        IcmpPing => "ICMP Ping",
        TcpAckServicePing => "TCP-ACK Service Ping",
        TcpSynServicePing => "TCP-SYN Service Ping",
        ArpPing => "ARP Ping",
        IcmpAndTcpAckServicePing => "ICMP & TCP-ACK Service Ping",
        IcmpAndArpPing => "ICMP & ARP Ping",
        TcpAckServiceAndArpPing => "TCP-ACK Service & ARP Ping",
        IcmpTcpAckServiceAndArpPing => "ICMP, TCP-ACK Service & ARP Ping",
        ConsiderAlive => "Consider Alive",
    }
);

canonical_inventory!(
    aggregate_statistic_wire_inventory,
    AggregateStatistic,
    {
        Count => ("count", Count),
        CMax => ("c_max", CMax),
        CSum => ("c_sum", CSum),
        Max => ("max", Max),
        Mean => ("mean", Mean),
        Min => ("min", Min),
        Sum => ("sum", Sum),
        Text => ("text", Text),
        Value => ("value", Value),
        WordCounts => ("word_counts", WordCounts),
    },
    aliases {}
);

canonical_inventory!(
    credential_format_wire_inventory,
    CredentialFormat,
    {
        Exe => ("exe", Exe),
        Pem => ("pem", Pem),
        Pgp => ("pgp", Pgp),
        Rpm => ("rpm", Rpm),
    },
    aliases {}
);

canonical_inventory!(
    credential_type_wire_inventory,
    CredentialType,
    {
        ClientCertificate => ("cc", ClientCertificate),
        Kerberos5 => ("krb5", Kerberos5),
        PasswordOnly => ("pw", PasswordOnly),
        PgpEncryptionKey => ("pgp", PgpEncryptionKey),
        SmimeCertificate => ("smime", SmimeCertificate),
        SnmpV1Or2c => ("snmp", SnmpV1Or2c),
        SnmpV3 => ("snmp", SnmpV1Or2c),
        UsernamePassword => ("up", UsernamePassword),
        UsernameSshKey => ("usk", UsernameSshKey),
    },
    aliases {
        "snmpv3" => SnmpV3,
    }
);

canonical_inventory!(
    credential_store_type_wire_inventory,
    CredentialStoreCredentialType,
    {
        ClientCertificate => ("cs_cc", ClientCertificate),
        PasswordOnly => ("cs_pw", PasswordOnly),
        PgpEncryptionKey => ("cs_pgp", PgpEncryptionKey),
        SmimeCertificate => ("cs_smime", SmimeCertificate),
        Snmp => ("cs_snmp", Snmp),
        UsernamePassword => ("cs_up", UsernamePassword),
        UsernameSshKey => ("cs_usk", UsernameSshKey),
    },
    aliases {}
);

canonical_inventory!(
    entity_type_wire_inventory,
    EntityType,
    {
        Alert => ("alert", Alert),
        Asset => ("asset", Asset),
        AuditReport => ("audit_report", AuditReport),
        CertBundAdv => ("cert_bund_adv", CertBundAdv),
        Config => ("config", Config),
        Cpe => ("cpe", Cpe),
        Credential => ("credential", Credential),
        Cve => ("cve", Cve),
        DfnCertAdv => ("dfn_cert_adv", DfnCertAdv),
        Filter => ("filter", Filter),
        Group => ("group", Group),
        Host => ("host", Host),
        Note => ("note", Note),
        Nvt => ("nvt", Nvt),
        OperatingSystem => ("operating_system", OperatingSystem),
        Override => ("override", Override),
        Permission => ("permission", Permission),
        Policy => ("policy", Policy),
        PortList => ("port_list", PortList),
        Report => ("report", Report),
        ReportConfig => ("report_config", ReportConfig),
        ReportFormat => ("report_format", ReportFormat),
        ResourceName => ("resource_name", ResourceName),
        Result => ("result", Result),
        Role => ("role", Role),
        Scanner => ("scanner", Scanner),
        Schedule => ("schedule", Schedule),
        Tag => ("tag", Tag),
        Target => ("target", Target),
        Task => ("task", Task),
        Ticket => ("ticket", Ticket),
        TlsCertificate => ("tls_certificate", TlsCertificate),
        User => ("user", User),
        Vulnerability => ("vulnerability", Vulnerability),
    },
    aliases {}
);

canonical_inventory!(
    resource_type_wire_inventory,
    ResourceType,
    {
        Alert => ("ALERT", Alert),
        Audit => ("TASK", Task),
        AuditReport => ("REPORT", Report),
        CertBundAdv => ("CERT_BUND_ADV", CertBundAdv),
        Config => ("CONFIG", Config),
        Cpe => ("CPE", Cpe),
        Credential => ("CREDENTIAL", Credential),
        Cve => ("CVE", Cve),
        DfnCertAdv => ("DFN_CERT_ADV", DfnCertAdv),
        Filter => ("FILTER", Filter),
        Group => ("GROUP", Group),
        Host => ("HOST", Host),
        Note => ("NOTE", Note),
        Nvt => ("NVT", Nvt),
        OperatingSystem => ("OS", OperatingSystem),
        Override => ("OVERRIDE", Override),
        Permission => ("PERMISSION", Permission),
        PortList => ("PORT_LIST", PortList),
        ReportFormat => ("REPORT_FORMAT", ReportFormat),
        Report => ("REPORT", Report),
        ReportConfig => ("REPORT_CONFIG", ReportConfig),
        Result => ("RESULT", Result),
        Role => ("ROLE", Role),
        Scanner => ("SCANNER", Scanner),
        Schedule => ("SCHEDULE", Schedule),
        Target => ("TARGET", Target),
        Task => ("TASK", Task),
        TlsCertificate => ("TLS_CERTIFICATE", TlsCertificate),
        User => ("USER", User),
    },
    aliases {}
);

canonical_inventory!(
    feed_type_wire_inventory,
    FeedType,
    {
        Nvt => ("NVT", Nvt),
        Cert => ("CERT", Cert),
        Scap => ("SCAP", Scap),
        Gvmd => ("GVMD_DATA", Gvmd),
    },
    aliases {}
);

canonical_inventory!(
    filter_type_wire_inventory,
    FilterType,
    {
        Alert => ("alert", Alert),
        Asset => ("asset", Asset),
        Config => ("config", Config),
        Credential => ("credential", Credential),
        Filter => ("filter", Filter),
        Group => ("group", Group),
        Host => ("host", Host),
        Note => ("note", Note),
        Override => ("override", Override),
        Permission => ("permission", Permission),
        PortList => ("port_list", PortList),
        Report => ("report", Report),
        ReportFormat => ("report_format", ReportFormat),
        Result => ("result", Result),
        Role => ("role", Role),
        Scanner => ("scanner", Scanner),
        Schedule => ("schedule", Schedule),
        Setting => ("setting", Setting),
        Tag => ("tag", Tag),
        Target => ("target", Target),
        Task => ("task", Task),
        Ticket => ("ticket", Ticket),
        TlsCertificate => ("tls_certificate", TlsCertificate),
        User => ("user", User),
        Vulnerability => ("vulnerability", Vulnerability),
    },
    aliases {}
);

canonical_inventory!(
    help_format_wire_inventory,
    HelpFormat,
    {
        Html => ("html", Html),
        Rnc => ("rnc", Rnc),
        Text => ("text", Text),
        Xml => ("xml", Xml),
    },
    aliases {}
);

canonical_inventory!(
    hosts_ordering_wire_inventory,
    HostsOrdering,
    {
        Sequential => ("sequential", Sequential),
        Random => ("random", Random),
        Reverse => ("reverse", Reverse),
    },
    aliases {}
);

canonical_inventory!(
    info_type_wire_inventory,
    InfoType,
    {
        CertBundAdv => ("CERT_BUND_ADV", CertBundAdv),
        Cpe => ("CPE", Cpe),
        Cve => ("CVE", Cve),
        DfnCertAdv => ("DFN_CERT_ADV", DfnCertAdv),
        Nvt => ("NVT", Nvt),
        Ovaldef => ("OVALDEF", Ovaldef),
    },
    aliases {}
);

canonical_inventory!(
    permission_subject_type_wire_inventory,
    PermissionSubjectType,
    {
        Group => ("group", Group),
        Role => ("role", Role),
        User => ("user", User),
    },
    aliases {}
);

canonical_inventory!(
    port_range_type_wire_inventory,
    PortRangeType,
    {
        Tcp => ("tcp", Tcp),
        Udp => ("udp", Udp),
    },
    aliases {
        "TCP" => Tcp,
        "UDP" => Udp,
    }
);

secondary_inventory!(
    port_range_type_command_name_inventory,
    PortRangeType,
    as_port_range_type,
    {
        Tcp => "TCP",
        Udp => "UDP",
    }
);

canonical_inventory!(
    report_format_type_wire_inventory,
    ReportFormatType,
    {
        Anonymous => ("anonymous", Anonymous),
        Csv => ("csv", Csv),
        Itg => ("itg", Itg),
        LaTexPdf => ("latex_pdf", LaTexPdf),
        Nbr => ("nbr", Nbr),
        Pdf => ("pdf", Pdf),
        Svg => ("svg", Svg),
        TxtReport => ("txt", TxtReport),
        Verinice => ("verinice", Verinice),
        Xml => ("xml", Xml),
    },
    aliases {}
);

canonical_inventory!(
    scanner_type_wire_inventory,
    ScannerType,
    {
        OpenVasScanner => ("OpenVAS", OpenVasScanner),
        CveScannerType => ("CVE", CveScannerType),
        GreenBoneSensorType => ("OSP", GreenBoneSensorType),
        OpenVasdScannerType => ("6", OpenVasdScannerType),
    },
    aliases {
        "2" => OpenVasScanner,
        "3" => CveScannerType,
        "5" => GreenBoneSensorType,
    }
);

secondary_inventory!(
    scanner_type_command_name_inventory,
    ScannerType,
    as_scanner_type,
    {
        OpenVasScanner => "2",
        CveScannerType => "3",
        GreenBoneSensorType => "5",
        OpenVasdScannerType => "6",
    }
);

canonical_inventory!(
    snmp_auth_algorithm_wire_inventory,
    SnmpAuthAlgorithm,
    {
        Md5 => ("md5", Md5),
        Sha1 => ("sha1", Sha1),
    },
    aliases {}
);

canonical_inventory!(
    snmp_privacy_algorithm_wire_inventory,
    SnmpPrivacyAlgorithm,
    {
        Aes => ("aes", Aes),
        Des => ("des", Des),
    },
    aliases {}
);

canonical_inventory!(
    sort_order_wire_inventory,
    SortOrder,
    {
        Ascending => ("ascending", Ascending),
        Descending => ("descending", Descending),
    },
    aliases {}
);

canonical_inventory!(
    severity_level_wire_inventory,
    SeverityLevel,
    {
        High => ("high", High),
        Medium => ("medium", Medium),
        Low => ("low", Low),
        Log => ("log", Log),
        Alarm => ("alarm", Alarm),
    },
    aliases {}
);

canonical_inventory!(
    ticket_status_wire_inventory,
    TicketStatus,
    {
        Open => ("open", Open),
        Fixed => ("fixed", Fixed),
        Closed => ("closed", Closed),
    },
    aliases {
        "Open" => Open,
        "Fixed" => Fixed,
        "Closed" => Closed,
    }
);

secondary_inventory!(
    ticket_status_command_name_inventory,
    TicketStatus,
    as_ticket_status,
    {
        Open => "Open",
        Fixed => "Fixed",
        Closed => "Closed",
    }
);

canonical_inventory!(
    user_auth_type_wire_inventory,
    UserAuthType,
    {
        File => ("file", File),
        LdapConnect => ("ldap_connect", LdapConnect),
        RadiusConnect => ("radius_connect", RadiusConnect),
    },
    aliases {}
);
