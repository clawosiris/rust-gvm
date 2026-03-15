mod common;
use std::str::FromStr;
use gvm_gmp::*;

#[test]
fn test_alertevent_taskrunstatuschanged_as_gmp_str() { assert_eq!(AlertEvent::TaskRunStatusChanged.as_gmp_str(), "task_run_status_changed"); }
#[test]
fn test_alertevent_taskrunstatuschanged_from_str() { assert_eq!(AlertEvent::from_str("task_run_status_changed").unwrap(), AlertEvent::TaskRunStatusChanged); }
#[test]
fn test_alertevent_updatedsecinfo_as_gmp_str() { assert_eq!(AlertEvent::UpdatedSecInfo.as_gmp_str(), "updated_secinfo"); }
#[test]
fn test_alertevent_updatedsecinfo_from_str() { assert_eq!(AlertEvent::from_str("updated_secinfo").unwrap(), AlertEvent::UpdatedSecInfo); }
#[test]
fn test_alertevent_newsecinfo_as_gmp_str() { assert_eq!(AlertEvent::NewSecInfo.as_gmp_str(), "new_secinfo"); }
#[test]
fn test_alertevent_newsecinfo_from_str() { assert_eq!(AlertEvent::from_str("new_secinfo").unwrap(), AlertEvent::NewSecInfo); }
#[test]
fn test_alertevent_invalid_string_returns_error() { assert!(AlertEvent::from_str("invalid").is_err()); }

#[test]
fn test_alertcondition_always_as_gmp_str() { assert_eq!(AlertCondition::Always.as_gmp_str(), "always"); }
#[test]
fn test_alertcondition_always_from_str() { assert_eq!(AlertCondition::from_str("always").unwrap(), AlertCondition::Always); }
#[test]
fn test_alertcondition_filtercountatleast_as_gmp_str() { assert_eq!(AlertCondition::FilterCountAtLeast.as_gmp_str(), "filter_count_at_least"); }
#[test]
fn test_alertcondition_filtercountatleast_from_str() { assert_eq!(AlertCondition::from_str("filter_count_at_least").unwrap(), AlertCondition::FilterCountAtLeast); }
#[test]
fn test_alertcondition_filtercountchanged_as_gmp_str() { assert_eq!(AlertCondition::FilterCountChanged.as_gmp_str(), "filter_count_changed"); }
#[test]
fn test_alertcondition_filtercountchanged_from_str() { assert_eq!(AlertCondition::from_str("filter_count_changed").unwrap(), AlertCondition::FilterCountChanged); }
#[test]
fn test_alertcondition_severityatleast_as_gmp_str() { assert_eq!(AlertCondition::SeverityAtLeast.as_gmp_str(), "severity_at_least"); }
#[test]
fn test_alertcondition_severityatleast_from_str() { assert_eq!(AlertCondition::from_str("severity_at_least").unwrap(), AlertCondition::SeverityAtLeast); }
#[test]
fn test_alertcondition_severitychanged_as_gmp_str() { assert_eq!(AlertCondition::SeverityChanged.as_gmp_str(), "severity_changed"); }
#[test]
fn test_alertcondition_severitychanged_from_str() { assert_eq!(AlertCondition::from_str("severity_changed").unwrap(), AlertCondition::SeverityChanged); }
#[test]
fn test_alertcondition_invalid_string_returns_error() { assert!(AlertCondition::from_str("invalid").is_err()); }

#[test]
fn test_alertmethod_email_as_gmp_str() { assert_eq!(AlertMethod::Email.as_gmp_str(), "email"); }
#[test]
fn test_alertmethod_email_from_str() { assert_eq!(AlertMethod::from_str("email").unwrap(), AlertMethod::Email); }
#[test]
fn test_alertmethod_httpget_as_gmp_str() { assert_eq!(AlertMethod::HttpGet.as_gmp_str(), "http_get"); }
#[test]
fn test_alertmethod_httpget_from_str() { assert_eq!(AlertMethod::from_str("http_get").unwrap(), AlertMethod::HttpGet); }
#[test]
fn test_alertmethod_scp_as_gmp_str() { assert_eq!(AlertMethod::Scp.as_gmp_str(), "scp"); }
#[test]
fn test_alertmethod_scp_from_str() { assert_eq!(AlertMethod::from_str("scp").unwrap(), AlertMethod::Scp); }
#[test]
fn test_alertmethod_sendemail_as_gmp_str() { assert_eq!(AlertMethod::SendEmail.as_gmp_str(), "send_email"); }
#[test]
fn test_alertmethod_sendemail_from_str() { assert_eq!(AlertMethod::from_str("send_email").unwrap(), AlertMethod::SendEmail); }
#[test]
fn test_alertmethod_smb_as_gmp_str() { assert_eq!(AlertMethod::Smb.as_gmp_str(), "smb"); }
#[test]
fn test_alertmethod_smb_from_str() { assert_eq!(AlertMethod::from_str("smb").unwrap(), AlertMethod::Smb); }
#[test]
fn test_alertmethod_snmp_as_gmp_str() { assert_eq!(AlertMethod::Snmp.as_gmp_str(), "snmp"); }
#[test]
fn test_alertmethod_snmp_from_str() { assert_eq!(AlertMethod::from_str("snmp").unwrap(), AlertMethod::Snmp); }
#[test]
fn test_alertmethod_sourcefireconnector_as_gmp_str() { assert_eq!(AlertMethod::SourcefireConnector.as_gmp_str(), "sourcefire_connector"); }
#[test]
fn test_alertmethod_sourcefireconnector_from_str() { assert_eq!(AlertMethod::from_str("sourcefire_connector").unwrap(), AlertMethod::SourcefireConnector); }
#[test]
fn test_alertmethod_starttask_as_gmp_str() { assert_eq!(AlertMethod::StartTask.as_gmp_str(), "start_task"); }
#[test]
fn test_alertmethod_starttask_from_str() { assert_eq!(AlertMethod::from_str("start_task").unwrap(), AlertMethod::StartTask); }
#[test]
fn test_alertmethod_syslog_as_gmp_str() { assert_eq!(AlertMethod::SysLog.as_gmp_str(), "syslog"); }
#[test]
fn test_alertmethod_syslog_from_str() { assert_eq!(AlertMethod::from_str("syslog").unwrap(), AlertMethod::SysLog); }
#[test]
fn test_alertmethod_tippingpoint_as_gmp_str() { assert_eq!(AlertMethod::TippingPoint.as_gmp_str(), "tippingpoint"); }
#[test]
fn test_alertmethod_tippingpoint_from_str() { assert_eq!(AlertMethod::from_str("tippingpoint").unwrap(), AlertMethod::TippingPoint); }
#[test]
fn test_alertmethod_verinicece_as_gmp_str() { assert_eq!(AlertMethod::VeriniceCe.as_gmp_str(), "verinice_ce"); }
#[test]
fn test_alertmethod_verinicece_from_str() { assert_eq!(AlertMethod::from_str("verinice_ce").unwrap(), AlertMethod::VeriniceCe); }
#[test]
fn test_alertmethod_verinicenet_as_gmp_str() { assert_eq!(AlertMethod::VeriniceNet.as_gmp_str(), "verinice_net"); }
#[test]
fn test_alertmethod_verinicenet_from_str() { assert_eq!(AlertMethod::from_str("verinice_net").unwrap(), AlertMethod::VeriniceNet); }
#[test]
fn test_alertmethod_alemba_as_gmp_str() { assert_eq!(AlertMethod::Alemba.as_gmp_str(), "alemba"); }
#[test]
fn test_alertmethod_alemba_from_str() { assert_eq!(AlertMethod::from_str("alemba").unwrap(), AlertMethod::Alemba); }
#[test]
fn test_alertmethod_invalid_string_returns_error() { assert!(AlertMethod::from_str("invalid").is_err()); }

#[test]
fn test_alivetest_scanconfigdefault_as_gmp_str() { assert_eq!(AliveTest::ScanConfigDefault.as_gmp_str(), "Scan Config Default"); }
#[test]
fn test_alivetest_scanconfigdefault_from_str() { assert_eq!(AliveTest::from_str("Scan Config Default").unwrap(), AliveTest::ScanConfigDefault); }
#[test]
fn test_alivetest_icmpping_as_gmp_str() { assert_eq!(AliveTest::IcmpPing.as_gmp_str(), "ICMP Ping"); }
#[test]
fn test_alivetest_icmpping_from_str() { assert_eq!(AliveTest::from_str("ICMP Ping").unwrap(), AliveTest::IcmpPing); }
#[test]
fn test_alivetest_tcpackserviceping_as_gmp_str() { assert_eq!(AliveTest::TcpAckServicePing.as_gmp_str(), "TCP-ACK Service Ping"); }
#[test]
fn test_alivetest_tcpackserviceping_from_str() { assert_eq!(AliveTest::from_str("TCP-ACK Service Ping").unwrap(), AliveTest::TcpAckServicePing); }
#[test]
fn test_alivetest_tcpsynserviceping_as_gmp_str() { assert_eq!(AliveTest::TcpSynServicePing.as_gmp_str(), "TCP-SYN Service Ping"); }
#[test]
fn test_alivetest_tcpsynserviceping_from_str() { assert_eq!(AliveTest::from_str("TCP-SYN Service Ping").unwrap(), AliveTest::TcpSynServicePing); }
#[test]
fn test_alivetest_arpping_as_gmp_str() { assert_eq!(AliveTest::ArpPing.as_gmp_str(), "ARP Ping"); }
#[test]
fn test_alivetest_arpping_from_str() { assert_eq!(AliveTest::from_str("ARP Ping").unwrap(), AliveTest::ArpPing); }
#[test]
fn test_alivetest_icmpandtcpackserviceping_as_gmp_str() { assert_eq!(AliveTest::IcmpAndTcpAckServicePing.as_gmp_str(), "ICMP, TCP-ACK Service Ping"); }
#[test]
fn test_alivetest_icmpandtcpackserviceping_from_str() { assert_eq!(AliveTest::from_str("ICMP, TCP-ACK Service Ping").unwrap(), AliveTest::IcmpAndTcpAckServicePing); }
#[test]
fn test_alivetest_icmpandarpping_as_gmp_str() { assert_eq!(AliveTest::IcmpAndArpPing.as_gmp_str(), "ICMP, ARP Ping"); }
#[test]
fn test_alivetest_icmpandarpping_from_str() { assert_eq!(AliveTest::from_str("ICMP, ARP Ping").unwrap(), AliveTest::IcmpAndArpPing); }
#[test]
fn test_alivetest_tcpackserviceandarpping_as_gmp_str() { assert_eq!(AliveTest::TcpAckServiceAndArpPing.as_gmp_str(), "TCP-ACK Service, ARP Ping"); }
#[test]
fn test_alivetest_tcpackserviceandarpping_from_str() { assert_eq!(AliveTest::from_str("TCP-ACK Service, ARP Ping").unwrap(), AliveTest::TcpAckServiceAndArpPing); }
#[test]
fn test_alivetest_icmptcpackserviceandarpping_as_gmp_str() { assert_eq!(AliveTest::IcmpTcpAckServiceAndArpPing.as_gmp_str(), "ICMP, TCP-ACK Service, ARP Ping"); }
#[test]
fn test_alivetest_icmptcpackserviceandarpping_from_str() { assert_eq!(AliveTest::from_str("ICMP, TCP-ACK Service, ARP Ping").unwrap(), AliveTest::IcmpTcpAckServiceAndArpPing); }
#[test]
fn test_alivetest_consideralive_as_gmp_str() { assert_eq!(AliveTest::ConsiderAlive.as_gmp_str(), "Consider Alive"); }
#[test]
fn test_alivetest_consideralive_from_str() { assert_eq!(AliveTest::from_str("Consider Alive").unwrap(), AliveTest::ConsiderAlive); }
#[test]
fn test_alivetest_invalid_string_returns_error() { assert!(AliveTest::from_str("invalid").is_err()); }

#[test]
fn test_aggregatestatistic_count_as_gmp_str() { assert_eq!(AggregateStatistic::Count.as_gmp_str(), "count"); }
#[test]
fn test_aggregatestatistic_count_from_str() { assert_eq!(AggregateStatistic::from_str("count").unwrap(), AggregateStatistic::Count); }
#[test]
fn test_aggregatestatistic_cmax_as_gmp_str() { assert_eq!(AggregateStatistic::CMax.as_gmp_str(), "c_max"); }
#[test]
fn test_aggregatestatistic_cmax_from_str() { assert_eq!(AggregateStatistic::from_str("c_max").unwrap(), AggregateStatistic::CMax); }
#[test]
fn test_aggregatestatistic_csum_as_gmp_str() { assert_eq!(AggregateStatistic::CSum.as_gmp_str(), "c_sum"); }
#[test]
fn test_aggregatestatistic_csum_from_str() { assert_eq!(AggregateStatistic::from_str("c_sum").unwrap(), AggregateStatistic::CSum); }
#[test]
fn test_aggregatestatistic_max_as_gmp_str() { assert_eq!(AggregateStatistic::Max.as_gmp_str(), "max"); }
#[test]
fn test_aggregatestatistic_max_from_str() { assert_eq!(AggregateStatistic::from_str("max").unwrap(), AggregateStatistic::Max); }
#[test]
fn test_aggregatestatistic_mean_as_gmp_str() { assert_eq!(AggregateStatistic::Mean.as_gmp_str(), "mean"); }
#[test]
fn test_aggregatestatistic_mean_from_str() { assert_eq!(AggregateStatistic::from_str("mean").unwrap(), AggregateStatistic::Mean); }
#[test]
fn test_aggregatestatistic_min_as_gmp_str() { assert_eq!(AggregateStatistic::Min.as_gmp_str(), "min"); }
#[test]
fn test_aggregatestatistic_min_from_str() { assert_eq!(AggregateStatistic::from_str("min").unwrap(), AggregateStatistic::Min); }
#[test]
fn test_aggregatestatistic_sum_as_gmp_str() { assert_eq!(AggregateStatistic::Sum.as_gmp_str(), "sum"); }
#[test]
fn test_aggregatestatistic_sum_from_str() { assert_eq!(AggregateStatistic::from_str("sum").unwrap(), AggregateStatistic::Sum); }
#[test]
fn test_aggregatestatistic_text_as_gmp_str() { assert_eq!(AggregateStatistic::Text.as_gmp_str(), "text"); }
#[test]
fn test_aggregatestatistic_text_from_str() { assert_eq!(AggregateStatistic::from_str("text").unwrap(), AggregateStatistic::Text); }
#[test]
fn test_aggregatestatistic_value_as_gmp_str() { assert_eq!(AggregateStatistic::Value.as_gmp_str(), "value"); }
#[test]
fn test_aggregatestatistic_value_from_str() { assert_eq!(AggregateStatistic::from_str("value").unwrap(), AggregateStatistic::Value); }
#[test]
fn test_aggregatestatistic_wordcounts_as_gmp_str() { assert_eq!(AggregateStatistic::WordCounts.as_gmp_str(), "word_counts"); }
#[test]
fn test_aggregatestatistic_wordcounts_from_str() { assert_eq!(AggregateStatistic::from_str("word_counts").unwrap(), AggregateStatistic::WordCounts); }
#[test]
fn test_aggregatestatistic_invalid_string_returns_error() { assert!(AggregateStatistic::from_str("invalid").is_err()); }

#[test]
fn test_credentialformat_exe_as_gmp_str() { assert_eq!(CredentialFormat::Exe.as_gmp_str(), "exe"); }
#[test]
fn test_credentialformat_exe_from_str() { assert_eq!(CredentialFormat::from_str("exe").unwrap(), CredentialFormat::Exe); }
#[test]
fn test_credentialformat_pem_as_gmp_str() { assert_eq!(CredentialFormat::Pem.as_gmp_str(), "pem"); }
#[test]
fn test_credentialformat_pem_from_str() { assert_eq!(CredentialFormat::from_str("pem").unwrap(), CredentialFormat::Pem); }
#[test]
fn test_credentialformat_pgp_as_gmp_str() { assert_eq!(CredentialFormat::Pgp.as_gmp_str(), "pgp"); }
#[test]
fn test_credentialformat_pgp_from_str() { assert_eq!(CredentialFormat::from_str("pgp").unwrap(), CredentialFormat::Pgp); }
#[test]
fn test_credentialformat_rpm_as_gmp_str() { assert_eq!(CredentialFormat::Rpm.as_gmp_str(), "rpm"); }
#[test]
fn test_credentialformat_rpm_from_str() { assert_eq!(CredentialFormat::from_str("rpm").unwrap(), CredentialFormat::Rpm); }
#[test]
fn test_credentialformat_invalid_string_returns_error() { assert!(CredentialFormat::from_str("invalid").is_err()); }

#[test]
fn test_credentialtype_clientcertificate_as_gmp_str() { assert_eq!(CredentialType::ClientCertificate.as_gmp_str(), "cc"); }
#[test]
fn test_credentialtype_clientcertificate_from_str() { assert_eq!(CredentialType::from_str("cc").unwrap(), CredentialType::ClientCertificate); }
#[test]
fn test_credentialtype_passwordonly_as_gmp_str() { assert_eq!(CredentialType::PasswordOnly.as_gmp_str(), "pw"); }
#[test]
fn test_credentialtype_passwordonly_from_str() { assert_eq!(CredentialType::from_str("pw").unwrap(), CredentialType::PasswordOnly); }
#[test]
fn test_credentialtype_snmpv1or2c_as_gmp_str() { assert_eq!(CredentialType::SnmpV1Or2c.as_gmp_str(), "snmp"); }
#[test]
fn test_credentialtype_snmpv1or2c_from_str() { assert_eq!(CredentialType::from_str("snmp").unwrap(), CredentialType::SnmpV1Or2c); }
#[test]
fn test_credentialtype_snmpv3_as_gmp_str() { assert_eq!(CredentialType::SnmpV3.as_gmp_str(), "snmpv3"); }
#[test]
fn test_credentialtype_snmpv3_from_str() { assert_eq!(CredentialType::from_str("snmpv3").unwrap(), CredentialType::SnmpV3); }
#[test]
fn test_credentialtype_usernamepassword_as_gmp_str() { assert_eq!(CredentialType::UsernamePassword.as_gmp_str(), "up"); }
#[test]
fn test_credentialtype_usernamepassword_from_str() { assert_eq!(CredentialType::from_str("up").unwrap(), CredentialType::UsernamePassword); }
#[test]
fn test_credentialtype_usernamesshkey_as_gmp_str() { assert_eq!(CredentialType::UsernameSshKey.as_gmp_str(), "usk"); }
#[test]
fn test_credentialtype_usernamesshkey_from_str() { assert_eq!(CredentialType::from_str("usk").unwrap(), CredentialType::UsernameSshKey); }
#[test]
fn test_credentialtype_invalid_string_returns_error() { assert!(CredentialType::from_str("invalid").is_err()); }

#[test] fn test_entitytype_alert_as_gmp_str() { assert_eq!(EntityType::Alert.as_gmp_str(), "alert"); }
#[test] fn test_entitytype_alert_from_str() { assert_eq!(EntityType::from_str("alert").unwrap(), EntityType::Alert); }
#[test] fn test_entitytype_asset_as_gmp_str() { assert_eq!(EntityType::Asset.as_gmp_str(), "asset"); }
#[test] fn test_entitytype_asset_from_str() { assert_eq!(EntityType::from_str("asset").unwrap(), EntityType::Asset); }
#[test] fn test_entitytype_auditreport_as_gmp_str() { assert_eq!(EntityType::AuditReport.as_gmp_str(), "audit_report"); }
#[test] fn test_entitytype_auditreport_from_str() { assert_eq!(EntityType::from_str("audit_report").unwrap(), EntityType::AuditReport); }
#[test] fn test_entitytype_certbundadv_as_gmp_str() { assert_eq!(EntityType::CertBundAdv.as_gmp_str(), "cert_bund_adv"); }
#[test] fn test_entitytype_certbundadv_from_str() { assert_eq!(EntityType::from_str("cert_bund_adv").unwrap(), EntityType::CertBundAdv); }
#[test] fn test_entitytype_config_as_gmp_str() { assert_eq!(EntityType::Config.as_gmp_str(), "config"); }
#[test] fn test_entitytype_config_from_str() { assert_eq!(EntityType::from_str("config").unwrap(), EntityType::Config); }
#[test] fn test_entitytype_cpe_as_gmp_str() { assert_eq!(EntityType::Cpe.as_gmp_str(), "cpe"); }
#[test] fn test_entitytype_cpe_from_str() { assert_eq!(EntityType::from_str("cpe").unwrap(), EntityType::Cpe); }
#[test] fn test_entitytype_credential_as_gmp_str() { assert_eq!(EntityType::Credential.as_gmp_str(), "credential"); }
#[test] fn test_entitytype_credential_from_str() { assert_eq!(EntityType::from_str("credential").unwrap(), EntityType::Credential); }
#[test] fn test_entitytype_cve_as_gmp_str() { assert_eq!(EntityType::Cve.as_gmp_str(), "cve"); }
#[test] fn test_entitytype_cve_from_str() { assert_eq!(EntityType::from_str("cve").unwrap(), EntityType::Cve); }
#[test] fn test_entitytype_dfncertadv_as_gmp_str() { assert_eq!(EntityType::DfnCertAdv.as_gmp_str(), "dfn_cert_adv"); }
#[test] fn test_entitytype_dfncertadv_from_str() { assert_eq!(EntityType::from_str("dfn_cert_adv").unwrap(), EntityType::DfnCertAdv); }
#[test] fn test_entitytype_filter_as_gmp_str() { assert_eq!(EntityType::Filter.as_gmp_str(), "filter"); }
#[test] fn test_entitytype_filter_from_str() { assert_eq!(EntityType::from_str("filter").unwrap(), EntityType::Filter); }
#[test] fn test_entitytype_group_as_gmp_str() { assert_eq!(EntityType::Group.as_gmp_str(), "group"); }
#[test] fn test_entitytype_group_from_str() { assert_eq!(EntityType::from_str("group").unwrap(), EntityType::Group); }
#[test] fn test_entitytype_host_as_gmp_str() { assert_eq!(EntityType::Host.as_gmp_str(), "host"); }
#[test] fn test_entitytype_host_from_str() { assert_eq!(EntityType::from_str("host").unwrap(), EntityType::Host); }
#[test] fn test_entitytype_note_as_gmp_str() { assert_eq!(EntityType::Note.as_gmp_str(), "note"); }
#[test] fn test_entitytype_note_from_str() { assert_eq!(EntityType::from_str("note").unwrap(), EntityType::Note); }
#[test] fn test_entitytype_nvt_as_gmp_str() { assert_eq!(EntityType::Nvt.as_gmp_str(), "nvt"); }
#[test] fn test_entitytype_nvt_from_str() { assert_eq!(EntityType::from_str("nvt").unwrap(), EntityType::Nvt); }
#[test] fn test_entitytype_operatingsystem_as_gmp_str() { assert_eq!(EntityType::OperatingSystem.as_gmp_str(), "operating_system"); }
#[test] fn test_entitytype_operatingsystem_from_str() { assert_eq!(EntityType::from_str("operating_system").unwrap(), EntityType::OperatingSystem); }
#[test] fn test_entitytype_override_as_gmp_str() { assert_eq!(EntityType::Override.as_gmp_str(), "override"); }
#[test] fn test_entitytype_override_from_str() { assert_eq!(EntityType::from_str("override").unwrap(), EntityType::Override); }
#[test] fn test_entitytype_permission_as_gmp_str() { assert_eq!(EntityType::Permission.as_gmp_str(), "permission"); }
#[test] fn test_entitytype_permission_from_str() { assert_eq!(EntityType::from_str("permission").unwrap(), EntityType::Permission); }
#[test] fn test_entitytype_policy_as_gmp_str() { assert_eq!(EntityType::Policy.as_gmp_str(), "policy"); }
#[test] fn test_entitytype_policy_from_str() { assert_eq!(EntityType::from_str("policy").unwrap(), EntityType::Policy); }
#[test] fn test_entitytype_portlist_as_gmp_str() { assert_eq!(EntityType::PortList.as_gmp_str(), "port_list"); }
#[test] fn test_entitytype_portlist_from_str() { assert_eq!(EntityType::from_str("port_list").unwrap(), EntityType::PortList); }
#[test] fn test_entitytype_report_as_gmp_str() { assert_eq!(EntityType::Report.as_gmp_str(), "report"); }
#[test] fn test_entitytype_report_from_str() { assert_eq!(EntityType::from_str("report").unwrap(), EntityType::Report); }
#[test] fn test_entitytype_reportconfig_as_gmp_str() { assert_eq!(EntityType::ReportConfig.as_gmp_str(), "report_config"); }
#[test] fn test_entitytype_reportconfig_from_str() { assert_eq!(EntityType::from_str("report_config").unwrap(), EntityType::ReportConfig); }
#[test] fn test_entitytype_reportformat_as_gmp_str() { assert_eq!(EntityType::ReportFormat.as_gmp_str(), "report_format"); }
#[test] fn test_entitytype_reportformat_from_str() { assert_eq!(EntityType::from_str("report_format").unwrap(), EntityType::ReportFormat); }
#[test] fn test_entitytype_resourcename_as_gmp_str() { assert_eq!(EntityType::ResourceName.as_gmp_str(), "resource_name"); }
#[test] fn test_entitytype_resourcename_from_str() { assert_eq!(EntityType::from_str("resource_name").unwrap(), EntityType::ResourceName); }
#[test] fn test_entitytype_result_as_gmp_str() { assert_eq!(EntityType::Result.as_gmp_str(), "result"); }
#[test] fn test_entitytype_result_from_str() { assert_eq!(EntityType::from_str("result").unwrap(), EntityType::Result); }
#[test] fn test_entitytype_role_as_gmp_str() { assert_eq!(EntityType::Role.as_gmp_str(), "role"); }
#[test] fn test_entitytype_role_from_str() { assert_eq!(EntityType::from_str("role").unwrap(), EntityType::Role); }
#[test] fn test_entitytype_scanner_as_gmp_str() { assert_eq!(EntityType::Scanner.as_gmp_str(), "scanner"); }
#[test] fn test_entitytype_scanner_from_str() { assert_eq!(EntityType::from_str("scanner").unwrap(), EntityType::Scanner); }
#[test] fn test_entitytype_schedule_as_gmp_str() { assert_eq!(EntityType::Schedule.as_gmp_str(), "schedule"); }
#[test] fn test_entitytype_schedule_from_str() { assert_eq!(EntityType::from_str("schedule").unwrap(), EntityType::Schedule); }
#[test] fn test_entitytype_tag_as_gmp_str() { assert_eq!(EntityType::Tag.as_gmp_str(), "tag"); }
#[test] fn test_entitytype_tag_from_str() { assert_eq!(EntityType::from_str("tag").unwrap(), EntityType::Tag); }
#[test] fn test_entitytype_target_as_gmp_str() { assert_eq!(EntityType::Target.as_gmp_str(), "target"); }
#[test] fn test_entitytype_target_from_str() { assert_eq!(EntityType::from_str("target").unwrap(), EntityType::Target); }
#[test] fn test_entitytype_task_as_gmp_str() { assert_eq!(EntityType::Task.as_gmp_str(), "task"); }
#[test] fn test_entitytype_task_from_str() { assert_eq!(EntityType::from_str("task").unwrap(), EntityType::Task); }
#[test] fn test_entitytype_ticket_as_gmp_str() { assert_eq!(EntityType::Ticket.as_gmp_str(), "ticket"); }
#[test] fn test_entitytype_ticket_from_str() { assert_eq!(EntityType::from_str("ticket").unwrap(), EntityType::Ticket); }
#[test] fn test_entitytype_tlscertificate_as_gmp_str() { assert_eq!(EntityType::TlsCertificate.as_gmp_str(), "tls_certificate"); }
#[test] fn test_entitytype_tlscertificate_from_str() { assert_eq!(EntityType::from_str("tls_certificate").unwrap(), EntityType::TlsCertificate); }
#[test] fn test_entitytype_user_as_gmp_str() { assert_eq!(EntityType::User.as_gmp_str(), "user"); }
#[test] fn test_entitytype_user_from_str() { assert_eq!(EntityType::from_str("user").unwrap(), EntityType::User); }
#[test] fn test_entitytype_vulnerability_as_gmp_str() { assert_eq!(EntityType::Vulnerability.as_gmp_str(), "vulnerability"); }
#[test] fn test_entitytype_vulnerability_from_str() { assert_eq!(EntityType::from_str("vulnerability").unwrap(), EntityType::Vulnerability); }
#[test] fn test_entitytype_invalid_string_returns_error() { assert!(EntityType::from_str("invalid").is_err()); }

#[test] fn test_feedtype_nvt_as_gmp_str() { assert_eq!(FeedType::Nvt.as_gmp_str(), "NVT"); }
#[test] fn test_feedtype_nvt_from_str() { assert_eq!(FeedType::from_str("NVT").unwrap(), FeedType::Nvt); }
#[test] fn test_feedtype_cert_as_gmp_str() { assert_eq!(FeedType::Cert.as_gmp_str(), "CERT"); }
#[test] fn test_feedtype_cert_from_str() { assert_eq!(FeedType::from_str("CERT").unwrap(), FeedType::Cert); }
#[test] fn test_feedtype_scap_as_gmp_str() { assert_eq!(FeedType::Scap.as_gmp_str(), "SCAP"); }
#[test] fn test_feedtype_scap_from_str() { assert_eq!(FeedType::from_str("SCAP").unwrap(), FeedType::Scap); }
#[test] fn test_feedtype_gvmd_as_gmp_str() { assert_eq!(FeedType::Gvmd.as_gmp_str(), "GVMD_DATA"); }
#[test] fn test_feedtype_gvmd_from_str() { assert_eq!(FeedType::from_str("GVMD_DATA").unwrap(), FeedType::Gvmd); }
#[test] fn test_feedtype_invalid_string_returns_error() { assert!(FeedType::from_str("invalid").is_err()); }

#[test] fn test_filtertype_alert_as_gmp_str() { assert_eq!(FilterType::Alert.as_gmp_str(), "alert"); }
#[test] fn test_filtertype_alert_from_str() { assert_eq!(FilterType::from_str("alert").unwrap(), FilterType::Alert); }
#[test] fn test_filtertype_asset_as_gmp_str() { assert_eq!(FilterType::Asset.as_gmp_str(), "asset"); }
#[test] fn test_filtertype_asset_from_str() { assert_eq!(FilterType::from_str("asset").unwrap(), FilterType::Asset); }
#[test] fn test_filtertype_config_as_gmp_str() { assert_eq!(FilterType::Config.as_gmp_str(), "config"); }
#[test] fn test_filtertype_config_from_str() { assert_eq!(FilterType::from_str("config").unwrap(), FilterType::Config); }
#[test] fn test_filtertype_credential_as_gmp_str() { assert_eq!(FilterType::Credential.as_gmp_str(), "credential"); }
#[test] fn test_filtertype_credential_from_str() { assert_eq!(FilterType::from_str("credential").unwrap(), FilterType::Credential); }
#[test] fn test_filtertype_filter_as_gmp_str() { assert_eq!(FilterType::Filter.as_gmp_str(), "filter"); }
#[test] fn test_filtertype_filter_from_str() { assert_eq!(FilterType::from_str("filter").unwrap(), FilterType::Filter); }
#[test] fn test_filtertype_group_as_gmp_str() { assert_eq!(FilterType::Group.as_gmp_str(), "group"); }
#[test] fn test_filtertype_group_from_str() { assert_eq!(FilterType::from_str("group").unwrap(), FilterType::Group); }
#[test] fn test_filtertype_host_as_gmp_str() { assert_eq!(FilterType::Host.as_gmp_str(), "host"); }
#[test] fn test_filtertype_host_from_str() { assert_eq!(FilterType::from_str("host").unwrap(), FilterType::Host); }
#[test] fn test_filtertype_note_as_gmp_str() { assert_eq!(FilterType::Note.as_gmp_str(), "note"); }
#[test] fn test_filtertype_note_from_str() { assert_eq!(FilterType::from_str("note").unwrap(), FilterType::Note); }
#[test] fn test_filtertype_override_as_gmp_str() { assert_eq!(FilterType::Override.as_gmp_str(), "override"); }
#[test] fn test_filtertype_override_from_str() { assert_eq!(FilterType::from_str("override").unwrap(), FilterType::Override); }
#[test] fn test_filtertype_permission_as_gmp_str() { assert_eq!(FilterType::Permission.as_gmp_str(), "permission"); }
#[test] fn test_filtertype_permission_from_str() { assert_eq!(FilterType::from_str("permission").unwrap(), FilterType::Permission); }
#[test] fn test_filtertype_portlist_as_gmp_str() { assert_eq!(FilterType::PortList.as_gmp_str(), "port_list"); }
#[test] fn test_filtertype_portlist_from_str() { assert_eq!(FilterType::from_str("port_list").unwrap(), FilterType::PortList); }
#[test] fn test_filtertype_report_as_gmp_str() { assert_eq!(FilterType::Report.as_gmp_str(), "report"); }
#[test] fn test_filtertype_report_from_str() { assert_eq!(FilterType::from_str("report").unwrap(), FilterType::Report); }
#[test] fn test_filtertype_reportformat_as_gmp_str() { assert_eq!(FilterType::ReportFormat.as_gmp_str(), "report_format"); }
#[test] fn test_filtertype_reportformat_from_str() { assert_eq!(FilterType::from_str("report_format").unwrap(), FilterType::ReportFormat); }
#[test] fn test_filtertype_result_as_gmp_str() { assert_eq!(FilterType::Result.as_gmp_str(), "result"); }
#[test] fn test_filtertype_result_from_str() { assert_eq!(FilterType::from_str("result").unwrap(), FilterType::Result); }
#[test] fn test_filtertype_role_as_gmp_str() { assert_eq!(FilterType::Role.as_gmp_str(), "role"); }
#[test] fn test_filtertype_role_from_str() { assert_eq!(FilterType::from_str("role").unwrap(), FilterType::Role); }
#[test] fn test_filtertype_scanner_as_gmp_str() { assert_eq!(FilterType::Scanner.as_gmp_str(), "scanner"); }
#[test] fn test_filtertype_scanner_from_str() { assert_eq!(FilterType::from_str("scanner").unwrap(), FilterType::Scanner); }
#[test] fn test_filtertype_schedule_as_gmp_str() { assert_eq!(FilterType::Schedule.as_gmp_str(), "schedule"); }
#[test] fn test_filtertype_schedule_from_str() { assert_eq!(FilterType::from_str("schedule").unwrap(), FilterType::Schedule); }
#[test] fn test_filtertype_setting_as_gmp_str() { assert_eq!(FilterType::Setting.as_gmp_str(), "setting"); }
#[test] fn test_filtertype_setting_from_str() { assert_eq!(FilterType::from_str("setting").unwrap(), FilterType::Setting); }
#[test] fn test_filtertype_tag_as_gmp_str() { assert_eq!(FilterType::Tag.as_gmp_str(), "tag"); }
#[test] fn test_filtertype_tag_from_str() { assert_eq!(FilterType::from_str("tag").unwrap(), FilterType::Tag); }
#[test] fn test_filtertype_target_as_gmp_str() { assert_eq!(FilterType::Target.as_gmp_str(), "target"); }
#[test] fn test_filtertype_target_from_str() { assert_eq!(FilterType::from_str("target").unwrap(), FilterType::Target); }
#[test] fn test_filtertype_task_as_gmp_str() { assert_eq!(FilterType::Task.as_gmp_str(), "task"); }
#[test] fn test_filtertype_task_from_str() { assert_eq!(FilterType::from_str("task").unwrap(), FilterType::Task); }
#[test] fn test_filtertype_ticket_as_gmp_str() { assert_eq!(FilterType::Ticket.as_gmp_str(), "ticket"); }
#[test] fn test_filtertype_ticket_from_str() { assert_eq!(FilterType::from_str("ticket").unwrap(), FilterType::Ticket); }
#[test] fn test_filtertype_tlscertificate_as_gmp_str() { assert_eq!(FilterType::TlsCertificate.as_gmp_str(), "tls_certificate"); }
#[test] fn test_filtertype_tlscertificate_from_str() { assert_eq!(FilterType::from_str("tls_certificate").unwrap(), FilterType::TlsCertificate); }
#[test] fn test_filtertype_user_as_gmp_str() { assert_eq!(FilterType::User.as_gmp_str(), "user"); }
#[test] fn test_filtertype_user_from_str() { assert_eq!(FilterType::from_str("user").unwrap(), FilterType::User); }
#[test] fn test_filtertype_vulnerability_as_gmp_str() { assert_eq!(FilterType::Vulnerability.as_gmp_str(), "vulnerability"); }
#[test] fn test_filtertype_vulnerability_from_str() { assert_eq!(FilterType::from_str("vulnerability").unwrap(), FilterType::Vulnerability); }
#[test] fn test_filtertype_invalid_string_returns_error() { assert!(FilterType::from_str("invalid").is_err()); }

#[test] fn test_helpformat_html_as_gmp_str() { assert_eq!(HelpFormat::Html.as_gmp_str(), "html"); }
#[test] fn test_helpformat_html_from_str() { assert_eq!(HelpFormat::from_str("html").unwrap(), HelpFormat::Html); }
#[test] fn test_helpformat_rnc_as_gmp_str() { assert_eq!(HelpFormat::Rnc.as_gmp_str(), "rnc"); }
#[test] fn test_helpformat_rnc_from_str() { assert_eq!(HelpFormat::from_str("rnc").unwrap(), HelpFormat::Rnc); }
#[test] fn test_helpformat_text_as_gmp_str() { assert_eq!(HelpFormat::Text.as_gmp_str(), "text"); }
#[test] fn test_helpformat_text_from_str() { assert_eq!(HelpFormat::from_str("text").unwrap(), HelpFormat::Text); }
#[test] fn test_helpformat_xml_as_gmp_str() { assert_eq!(HelpFormat::Xml.as_gmp_str(), "xml"); }
#[test] fn test_helpformat_xml_from_str() { assert_eq!(HelpFormat::from_str("xml").unwrap(), HelpFormat::Xml); }
#[test] fn test_helpformat_invalid_string_returns_error() { assert!(HelpFormat::from_str("invalid").is_err()); }

#[test] fn test_hostsordering_sequential_as_gmp_str() { assert_eq!(HostsOrdering::Sequential.as_gmp_str(), "sequential"); }
#[test] fn test_hostsordering_sequential_from_str() { assert_eq!(HostsOrdering::from_str("sequential").unwrap(), HostsOrdering::Sequential); }
#[test] fn test_hostsordering_random_as_gmp_str() { assert_eq!(HostsOrdering::Random.as_gmp_str(), "random"); }
#[test] fn test_hostsordering_random_from_str() { assert_eq!(HostsOrdering::from_str("random").unwrap(), HostsOrdering::Random); }
#[test] fn test_hostsordering_reverse_as_gmp_str() { assert_eq!(HostsOrdering::Reverse.as_gmp_str(), "reverse"); }
#[test] fn test_hostsordering_reverse_from_str() { assert_eq!(HostsOrdering::from_str("reverse").unwrap(), HostsOrdering::Reverse); }
#[test] fn test_hostsordering_invalid_string_returns_error() { assert!(HostsOrdering::from_str("invalid").is_err()); }

#[test] fn test_infotype_certbundadv_as_gmp_str() { assert_eq!(InfoType::CertBundAdv.as_gmp_str(), "CERT_BUND_ADV"); }
#[test] fn test_infotype_certbundadv_from_str() { assert_eq!(InfoType::from_str("CERT_BUND_ADV").unwrap(), InfoType::CertBundAdv); }
#[test] fn test_infotype_cpe_as_gmp_str() { assert_eq!(InfoType::Cpe.as_gmp_str(), "CPE"); }
#[test] fn test_infotype_cpe_from_str() { assert_eq!(InfoType::from_str("CPE").unwrap(), InfoType::Cpe); }
#[test] fn test_infotype_cve_as_gmp_str() { assert_eq!(InfoType::Cve.as_gmp_str(), "CVE"); }
#[test] fn test_infotype_cve_from_str() { assert_eq!(InfoType::from_str("CVE").unwrap(), InfoType::Cve); }
#[test] fn test_infotype_dfncertadv_as_gmp_str() { assert_eq!(InfoType::DfnCertAdv.as_gmp_str(), "DFN_CERT_ADV"); }
#[test] fn test_infotype_dfncertadv_from_str() { assert_eq!(InfoType::from_str("DFN_CERT_ADV").unwrap(), InfoType::DfnCertAdv); }
#[test] fn test_infotype_nvt_as_gmp_str() { assert_eq!(InfoType::Nvt.as_gmp_str(), "NVT"); }
#[test] fn test_infotype_nvt_from_str() { assert_eq!(InfoType::from_str("NVT").unwrap(), InfoType::Nvt); }
#[test] fn test_infotype_ovaldef_as_gmp_str() { assert_eq!(InfoType::Ovaldef.as_gmp_str(), "OVALDEF"); }
#[test] fn test_infotype_ovaldef_from_str() { assert_eq!(InfoType::from_str("OVALDEF").unwrap(), InfoType::Ovaldef); }
#[test] fn test_infotype_invalid_string_returns_error() { assert!(InfoType::from_str("invalid").is_err()); }

#[test] fn test_permissionsubjecttype_group_as_gmp_str() { assert_eq!(PermissionSubjectType::Group.as_gmp_str(), "group"); }
#[test] fn test_permissionsubjecttype_group_from_str() { assert_eq!(PermissionSubjectType::Group.as_gmp_str(), "group"); assert_eq!(PermissionSubjectType::from_str("group").unwrap(), PermissionSubjectType::Group); }
#[test] fn test_permissionsubjecttype_role_as_gmp_str() { assert_eq!(PermissionSubjectType::Role.as_gmp_str(), "role"); }
#[test] fn test_permissionsubjecttype_role_from_str() { assert_eq!(PermissionSubjectType::from_str("role").unwrap(), PermissionSubjectType::Role); }
#[test] fn test_permissionsubjecttype_user_as_gmp_str() { assert_eq!(PermissionSubjectType::User.as_gmp_str(), "user"); }
#[test] fn test_permissionsubjecttype_user_from_str() { assert_eq!(PermissionSubjectType::from_str("user").unwrap(), PermissionSubjectType::User); }
#[test] fn test_permissionsubjecttype_invalid_string_returns_error() { assert!(PermissionSubjectType::from_str("invalid").is_err()); }

#[test] fn test_portrangetype_tcp_as_gmp_str() { assert_eq!(PortRangeType::Tcp.as_gmp_str(), "tcp"); }
#[test] fn test_portrangetype_tcp_from_str() { assert_eq!(PortRangeType::from_str("tcp").unwrap(), PortRangeType::Tcp); }
#[test] fn test_portrangetype_udp_as_gmp_str() { assert_eq!(PortRangeType::Udp.as_gmp_str(), "udp"); }
#[test] fn test_portrangetype_udp_from_str() { assert_eq!(PortRangeType::from_str("udp").unwrap(), PortRangeType::Udp); }
#[test] fn test_portrangetype_invalid_string_returns_error() { assert!(PortRangeType::from_str("invalid").is_err()); }

#[test] fn test_reportformattype_anonymous_as_gmp_str() { assert_eq!(ReportFormatType::Anonymous.as_gmp_str(), "anonymous"); }
#[test] fn test_reportformattype_anonymous_from_str() { assert_eq!(ReportFormatType::from_str("anonymous").unwrap(), ReportFormatType::Anonymous); }
#[test] fn test_reportformattype_csv_as_gmp_str() { assert_eq!(ReportFormatType::Csv.as_gmp_str(), "csv"); }
#[test] fn test_reportformattype_csv_from_str() { assert_eq!(ReportFormatType::from_str("csv").unwrap(), ReportFormatType::Csv); }
#[test] fn test_reportformattype_itg_as_gmp_str() { assert_eq!(ReportFormatType::Itg.as_gmp_str(), "itg"); }
#[test] fn test_reportformattype_itg_from_str() { assert_eq!(ReportFormatType::from_str("itg").unwrap(), ReportFormatType::Itg); }
#[test] fn test_reportformattype_latexpdf_as_gmp_str() { assert_eq!(ReportFormatType::LaTexPdf.as_gmp_str(), "latex_pdf"); }
#[test] fn test_reportformattype_latexpdf_from_str() { assert_eq!(ReportFormatType::from_str("latex_pdf").unwrap(), ReportFormatType::LaTexPdf); }
#[test] fn test_reportformattype_nbr_as_gmp_str() { assert_eq!(ReportFormatType::Nbr.as_gmp_str(), "nbr"); }
#[test] fn test_reportformattype_nbr_from_str() { assert_eq!(ReportFormatType::from_str("nbr").unwrap(), ReportFormatType::Nbr); }
#[test] fn test_reportformattype_pdf_as_gmp_str() { assert_eq!(ReportFormatType::Pdf.as_gmp_str(), "pdf"); }
#[test] fn test_reportformattype_pdf_from_str() { assert_eq!(ReportFormatType::from_str("pdf").unwrap(), ReportFormatType::Pdf); }
#[test] fn test_reportformattype_svg_as_gmp_str() { assert_eq!(ReportFormatType::Svg.as_gmp_str(), "svg"); }
#[test] fn test_reportformattype_svg_from_str() { assert_eq!(ReportFormatType::from_str("svg").unwrap(), ReportFormatType::Svg); }
#[test] fn test_reportformattype_txtreport_as_gmp_str() { assert_eq!(ReportFormatType::TxtReport.as_gmp_str(), "txt"); }
#[test] fn test_reportformattype_txtreport_from_str() { assert_eq!(ReportFormatType::from_str("txt").unwrap(), ReportFormatType::TxtReport); }
#[test] fn test_reportformattype_verinice_as_gmp_str() { assert_eq!(ReportFormatType::Verinice.as_gmp_str(), "verinice"); }
#[test] fn test_reportformattype_verinice_from_str() { assert_eq!(ReportFormatType::from_str("verinice").unwrap(), ReportFormatType::Verinice); }
#[test] fn test_reportformattype_xml_as_gmp_str() { assert_eq!(ReportFormatType::Xml.as_gmp_str(), "xml"); }
#[test] fn test_reportformattype_xml_from_str() { assert_eq!(ReportFormatType::from_str("xml").unwrap(), ReportFormatType::Xml); }
#[test] fn test_reportformattype_invalid_string_returns_error() { assert!(ReportFormatType::from_str("invalid").is_err()); }

#[test] fn test_scannertype_openvasscanner_as_gmp_str() { assert_eq!(ScannerType::OpenVasScanner.as_gmp_str(), "OpenVAS"); }
#[test] fn test_scannertype_openvasscanner_from_str() { assert_eq!(ScannerType::from_str("OpenVAS").unwrap(), ScannerType::OpenVasScanner); }
#[test] fn test_scannertype_cvescannertype_as_gmp_str() { assert_eq!(ScannerType::CveScannerType.as_gmp_str(), "CVE"); }
#[test] fn test_scannertype_cvescannertype_from_str() { assert_eq!(ScannerType::from_str("CVE").unwrap(), ScannerType::CveScannerType); }
#[test] fn test_scannertype_greenbonesensortype_as_gmp_str() { assert_eq!(ScannerType::GreenBoneSensorType.as_gmp_str(), "OSP"); }
#[test] fn test_scannertype_greenbonesensortype_from_str() { assert_eq!(ScannerType::from_str("OSP").unwrap(), ScannerType::GreenBoneSensorType); }
#[test] fn test_scannertype_invalid_string_returns_error() { assert!(ScannerType::from_str("invalid").is_err()); }

#[test] fn test_snmpauthalgorithm_md5_as_gmp_str() { assert_eq!(SnmpAuthAlgorithm::Md5.as_gmp_str(), "md5"); }
#[test] fn test_snmpauthalgorithm_md5_from_str() { assert_eq!(SnmpAuthAlgorithm::from_str("md5").unwrap(), SnmpAuthAlgorithm::Md5); }
#[test] fn test_snmpauthalgorithm_sha1_as_gmp_str() { assert_eq!(SnmpAuthAlgorithm::Sha1.as_gmp_str(), "sha1"); }
#[test] fn test_snmpauthalgorithm_sha1_from_str() { assert_eq!(SnmpAuthAlgorithm::from_str("sha1").unwrap(), SnmpAuthAlgorithm::Sha1); }
#[test] fn test_snmpauthalgorithm_invalid_string_returns_error() { assert!(SnmpAuthAlgorithm::from_str("invalid").is_err()); }

#[test] fn test_snmpprivacyalgorithm_aes_as_gmp_str() { assert_eq!(SnmpPrivacyAlgorithm::Aes.as_gmp_str(), "aes"); }
#[test] fn test_snmpprivacyalgorithm_aes_from_str() { assert_eq!(SnmpPrivacyAlgorithm::from_str("aes").unwrap(), SnmpPrivacyAlgorithm::Aes); }
#[test] fn test_snmpprivacyalgorithm_des_as_gmp_str() { assert_eq!(SnmpPrivacyAlgorithm::Des.as_gmp_str(), "des"); }
#[test] fn test_snmpprivacyalgorithm_des_from_str() { assert_eq!(SnmpPrivacyAlgorithm::from_str("des").unwrap(), SnmpPrivacyAlgorithm::Des); }
#[test] fn test_snmpprivacyalgorithm_invalid_string_returns_error() { assert!(SnmpPrivacyAlgorithm::from_str("invalid").is_err()); }

#[test] fn test_sortorder_ascending_as_gmp_str() { assert_eq!(SortOrder::Ascending.as_gmp_str(), "ascending"); }
#[test] fn test_sortorder_ascending_from_str() { assert_eq!(SortOrder::from_str("ascending").unwrap(), SortOrder::Ascending); }
#[test] fn test_sortorder_descending_as_gmp_str() { assert_eq!(SortOrder::Descending.as_gmp_str(), "descending"); }
#[test] fn test_sortorder_descending_from_str() { assert_eq!(SortOrder::from_str("descending").unwrap(), SortOrder::Descending); }
#[test] fn test_sortorder_invalid_string_returns_error() { assert!(SortOrder::from_str("invalid").is_err()); }

#[test] fn test_severitylevel_high_as_gmp_str() { assert_eq!(SeverityLevel::High.as_gmp_str(), "high"); }
#[test] fn test_severitylevel_high_from_str() { assert_eq!(SeverityLevel::from_str("high").unwrap(), SeverityLevel::High); }
#[test] fn test_severitylevel_medium_as_gmp_str() { assert_eq!(SeverityLevel::Medium.as_gmp_str(), "medium"); }
#[test] fn test_severitylevel_medium_from_str() { assert_eq!(SeverityLevel::from_str("medium").unwrap(), SeverityLevel::Medium); }
#[test] fn test_severitylevel_low_as_gmp_str() { assert_eq!(SeverityLevel::Low.as_gmp_str(), "low"); }
#[test] fn test_severitylevel_low_from_str() { assert_eq!(SeverityLevel::from_str("low").unwrap(), SeverityLevel::Low); }
#[test] fn test_severitylevel_log_as_gmp_str() { assert_eq!(SeverityLevel::Log.as_gmp_str(), "log"); }
#[test] fn test_severitylevel_log_from_str() { assert_eq!(SeverityLevel::from_str("log").unwrap(), SeverityLevel::Log); }
#[test] fn test_severitylevel_alarm_as_gmp_str() { assert_eq!(SeverityLevel::Alarm.as_gmp_str(), "alarm"); }
#[test] fn test_severitylevel_alarm_from_str() { assert_eq!(SeverityLevel::from_str("alarm").unwrap(), SeverityLevel::Alarm); }
#[test] fn test_severitylevel_invalid_string_returns_error() { assert!(SeverityLevel::from_str("invalid").is_err()); }

#[test] fn test_ticketstatus_open_as_gmp_str() { assert_eq!(TicketStatus::Open.as_gmp_str(), "open"); }
#[test] fn test_ticketstatus_open_from_str() { assert_eq!(TicketStatus::from_str("open").unwrap(), TicketStatus::Open); }
#[test] fn test_ticketstatus_fixed_as_gmp_str() { assert_eq!(TicketStatus::Fixed.as_gmp_str(), "fixed"); }
#[test] fn test_ticketstatus_fixed_from_str() { assert_eq!(TicketStatus::from_str("fixed").unwrap(), TicketStatus::Fixed); }
#[test] fn test_ticketstatus_closed_as_gmp_str() { assert_eq!(TicketStatus::Closed.as_gmp_str(), "closed"); }
#[test] fn test_ticketstatus_closed_from_str() { assert_eq!(TicketStatus::from_str("closed").unwrap(), TicketStatus::Closed); }
#[test] fn test_ticketstatus_invalid_string_returns_error() { assert!(TicketStatus::from_str("invalid").is_err()); }

#[test] fn test_userauthtype_file_as_gmp_str() { assert_eq!(UserAuthType::File.as_gmp_str(), "file"); }
#[test] fn test_userauthtype_file_from_str() { assert_eq!(UserAuthType::from_str("file").unwrap(), UserAuthType::File); }
#[test] fn test_userauthtype_ldapconnect_as_gmp_str() { assert_eq!(UserAuthType::LdapConnect.as_gmp_str(), "ldap_connect"); }
#[test] fn test_userauthtype_ldapconnect_from_str() { assert_eq!(UserAuthType::from_str("ldap_connect").unwrap(), UserAuthType::LdapConnect); }
#[test] fn test_userauthtype_radiusconnect_as_gmp_str() { assert_eq!(UserAuthType::RadiusConnect.as_gmp_str(), "radius_connect"); }
#[test] fn test_userauthtype_radiusconnect_from_str() { assert_eq!(UserAuthType::from_str("radius_connect").unwrap(), UserAuthType::RadiusConnect); }
#[test] fn test_userauthtype_invalid_string_returns_error() { assert!(UserAuthType::from_str("invalid").is_err()); }
