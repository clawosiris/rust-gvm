// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! GMP response XML generation.

use std::fmt::Write;

use uuid::Uuid;

use crate::util::xml_escape_attr;

const LARGE_REPORT_FORMAT_ID: Uuid = Uuid::from_u128(0xc402cc3e_b531_11e1_9163_406186ea4fc5);
/// Well-known report-format UUID that returns a binary export payload in the mock server.
pub const REPORT_EXPORT_BINARY_FORMAT_ID: Uuid =
    Uuid::from_u128(0xaaaaaaaa_aaaa_aaaa_aaaa_aaaaaaaaaaaa);
/// Well-known report-format UUID that returns a nested-XML export payload in the mock server.
pub const REPORT_EXPORT_XML_FORMAT_ID: Uuid =
    Uuid::from_u128(0xbbbbbbbb_bbbb_bbbb_bbbb_bbbbbbbbbbbb);
const PORTS: [u16; 5] = [22, 80, 443, 8080, 8443];
const SEVERITIES: [&str; 7] = ["2.1", "4.3", "5.0", "6.5", "7.5", "8.1", "9.8"];
const DESCRIPTION_SENTENCE: &str =
    "Synthetic result payload generated for large-response integration testing. ";
const REPORT_EXPORT_BINARY_BODY: &str = "SGVsbG8gUERG";

/// Configuration for synthetic large report generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LargeReportConfig {
    /// Number of `<result>` elements to generate.
    pub result_count: usize,
    /// Approximate bytes of filler text per result's `<description>`.
    pub result_payload_bytes: usize,
}

impl Default for LargeReportConfig {
    fn default() -> Self {
        Self {
            result_count: 1_000,
            result_payload_bytes: 512,
        }
    }
}

/// Known GMP commands that the mock server recognizes.
pub static KNOWN_COMMANDS: &[&str] = &[
    "authenticate",
    "create_agent_group",
    "create_alert",
    "create_asset",
    "create_config",
    "create_credential",
    "create_filter",
    "create_group",
    "create_note",
    "create_override",
    "create_permission",
    "create_port_list",
    "create_port_range",
    "create_report",
    "create_report_config",
    "create_report_format",
    "create_role",
    "create_scanner",
    "create_schedule",
    "create_tag",
    "create_target",
    "create_task",
    "create_ticket",
    "create_tls_certificate",
    "create_user",
    "delete_agent_group",
    "delete_alert",
    "delete_asset",
    "delete_config",
    "delete_credential",
    "delete_filter",
    "delete_group",
    "delete_note",
    "delete_override",
    "delete_permission",
    "delete_port_list",
    "delete_port_range",
    "delete_report",
    "delete_report_config",
    "delete_report_format",
    "delete_role",
    "delete_scanner",
    "delete_schedule",
    "delete_tag",
    "delete_target",
    "delete_task",
    "delete_ticket",
    "delete_user",
    "describe_auth",
    "empty_trashcan",
    "get_agent_groups",
    "get_aggregates",
    "get_alerts",
    "get_assets",
    "get_configs",
    "get_credentials",
    "get_features",
    "get_feeds",
    "get_filters",
    "get_groups",
    "get_info",
    "get_license",
    "get_notes",
    "get_nvt_families",
    "get_nvts",
    "get_overrides",
    "get_permissions",
    "get_port_lists",
    "get_preferences",
    "get_report_configs",
    "get_report_formats",
    "get_reports",
    "get_resource_names",
    "get_results",
    "get_roles",
    "get_scanners",
    "get_schedules",
    "get_settings",
    "get_system_reports",
    "get_tags",
    "get_targets",
    "get_tasks",
    "get_tickets",
    "get_tls_certificates",
    "get_users",
    "get_version",
    "get_vulns",
    "help",
    "modify_agent_group",
    "modify_alert",
    "modify_asset",
    "modify_auth",
    "modify_config",
    "modify_credential",
    "modify_filter",
    "modify_group",
    "modify_license",
    "modify_note",
    "modify_override",
    "modify_permission",
    "modify_port_list",
    "modify_report_config",
    "modify_report_format",
    "modify_role",
    "modify_scanner",
    "modify_schedule",
    "modify_setting",
    "modify_tag",
    "modify_target",
    "modify_task",
    "modify_ticket",
    "modify_tls_certificate",
    "modify_user",
    "move_task",
    "restore",
    "resume_task",
    "run_wizard",
    "start_task",
    "stop_task",
    "sync_config",
    "test_alert",
    "verify_report_format",
    "verify_scanner",
];

/// Check if a command name is known.
pub fn is_known_command(name: &str) -> bool {
    KNOWN_COMMANDS.binary_search(&name).is_ok()
}

/// Generate an echo-mode response for a command.
///
/// - `create_*` → status 201 with a generated UUID
/// - `get_version` → status 200 with version element
/// - all other known → status 200
/// - unknown → status 400
pub fn echo_response(command_name: &str, version: &str) -> Vec<u8> {
    if !is_known_command(command_name) {
        return error_response(command_name, 400, "Unknown command");
    }

    if command_name == "get_version" {
        return format!(
            "<get_version_response status=\"200\" status_text=\"OK\">\
             <version>{version}</version>\
             </get_version_response>"
        )
        .into_bytes();
    }

    if command_name == "authenticate" {
        return format!(
            "<authenticate_response status=\"200\" status_text=\"OK\">\
             <role>Admin</role>\
             <timezone>UTC</timezone>\
             </authenticate_response>"
        )
        .into_bytes();
    }

    if command_name.starts_with("create_") {
        let id = Uuid::new_v4();
        return format!(
            "<{command_name}_response status=\"201\" \
             status_text=\"OK, resource created\" \
             id=\"{id}\"/>"
        )
        .into_bytes();
    }

    if command_name.starts_with("start_") || command_name.starts_with("resume_") {
        let report_id = Uuid::new_v4();
        return format!(
            "<{command_name}_response status=\"202\" status_text=\"OK\">\
             <report_id>{report_id}</report_id>\
             </{command_name}_response>"
        )
        .into_bytes();
    }

    // Default: 200 OK
    format!("<{command_name}_response status=\"200\" status_text=\"OK\"/>").into_bytes()
}

/// Generate an error response.
pub fn error_response(command_name: &str, status: u16, status_text: &str) -> Vec<u8> {
    let escaped_text = xml_escape_attr(status_text);
    format!("<{command_name}_response status=\"{status}\" status_text=\"{escaped_text}\"/>")
        .into_bytes()
}

/// Generate a `get_version` response for a specific version.
pub fn version_response(version: &str) -> Vec<u8> {
    format!(
        "<get_version_response status=\"200\" status_text=\"OK\">\
         <version>{version}</version>\
         </get_version_response>"
    )
    .into_bytes()
}

/// Generate a deterministic synthetic `get_reports_response`.
#[must_use]
pub fn generate_large_report(report_id: Uuid, config: &LargeReportConfig) -> String {
    let per_result_estimate = config.result_payload_bytes.saturating_add(320);
    let estimated_len = config
        .result_count
        .saturating_mul(per_result_estimate)
        .saturating_add(512);
    let description = build_description_payload(config.result_payload_bytes);
    let mut xml = String::with_capacity(estimated_len);

    write!(
        xml,
        "<get_reports_response status=\"200\" status_text=\"OK\">\
         <report id=\"{report_id}\" format_id=\"{format_id}\" content_type=\"text/xml\">\
         <report id=\"{report_id}\">\
         <results max=\"{count}\" start=\"1\">",
        format_id = LARGE_REPORT_FORMAT_ID,
        count = config.result_count,
    )
    .expect("writing XML into String should not fail");

    for i in 0..config.result_count {
        let result_id = Uuid::new_v5(&report_id, &(i as u64).to_le_bytes());
        let host_octet = (i % 254) + 1;
        let port = PORTS[i % PORTS.len()];
        let severity = SEVERITIES[i % SEVERITIES.len()];
        let threat = threat_for_severity(severity);
        let oid = 10_000 + i;

        write!(
            xml,
            "<result id=\"{result_id}\">\
             <host>10.0.0.{host_octet}</host>\
             <port>{port}/tcp</port>\
             <nvt oid=\"1.3.6.1.4.1.25623.1.0.{oid}\">\
             <name>Test NVT {i}</name>\
             <type>nvt</type>\
             </nvt>\
             <severity>{severity}</severity>\
             <threat>{threat}</threat>\
             <description>{description}</description>\
             </result>",
        )
        .expect("writing XML into String should not fail");
    }

    write!(
        xml,
        "</results>\
         <result_count><full>{count}</full><filtered>{count}</filtered></result_count>\
         </report>\
         </report>\
         </get_reports_response>",
        count = config.result_count,
    )
    .expect("writing XML into String should not fail");

    xml
}

/// Generate a deterministic base64-backed report export response.
#[must_use]
pub fn generate_binary_report_export(report_id: Uuid, format_id: Uuid) -> String {
    format!(
        "<get_reports_response status=\"200\" status_text=\"OK\">\
         <report id=\"{report_id}\" format_id=\"{format_id}\" extension=\"pdf\" content_type=\"application/pdf\">{REPORT_EXPORT_BINARY_BODY}</report>\
         </get_reports_response>"
    )
}

/// Generate a deterministic nested-XML report export response.
#[must_use]
pub fn generate_xml_report_export(report_id: Uuid, format_id: Uuid) -> String {
    format!(
        "<get_reports_response status=\"200\" status_text=\"OK\">\
         <report id=\"{report_id}\" format_id=\"{format_id}\" extension=\"xml\" content_type=\"text/xml\">\
         <report id=\"{report_id}\"><results><result id=\"result-1\"/></results></report>\
         </report>\
         </get_reports_response>"
    )
}

fn build_description_payload(target_bytes: usize) -> String {
    let mut description = String::with_capacity(target_bytes);
    while description.len() < target_bytes {
        let remaining = target_bytes - description.len();
        if remaining >= DESCRIPTION_SENTENCE.len() {
            description.push_str(DESCRIPTION_SENTENCE);
        } else {
            description.push_str(&DESCRIPTION_SENTENCE[..remaining]);
        }
    }
    description
}

fn threat_for_severity(severity: &str) -> &'static str {
    match severity {
        "2.1" | "4.3" => "Low",
        "5.0" | "6.5" => "Medium",
        _ => "High",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::events::Event;
    use quick_xml::{Reader, XmlVersion};

    fn extract_descriptions(xml: &str) -> Vec<String> {
        let mut reader = Reader::from_str(xml);
        let mut descriptions = Vec::new();
        let mut in_description = false;

        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) if e.name().as_ref() == b"description" => {
                    in_description = true;
                }
                Ok(Event::Text(text)) if in_description => {
                    descriptions.push(
                        text.xml_content(XmlVersion::Implicit1_0)
                            .expect("description text should decode")
                            .into_owned(),
                    );
                }
                Ok(Event::End(ref e)) if e.name().as_ref() == b"description" => {
                    in_description = false;
                }
                Ok(Event::Eof) => break,
                Ok(_) => {}
                Err(error) => panic!("unexpected xml parse failure: {error}"),
            }
        }

        descriptions
    }

    #[test]
    fn test_known_commands() {
        assert!(is_known_command("get_tasks"));
        assert!(is_known_command("create_task"));
        assert!(is_known_command("authenticate"));
        assert!(!is_known_command("do_something_weird"));
    }

    #[test]
    fn test_echo_get_version() {
        let resp = echo_response("get_version", "22.5");
        let text = std::str::from_utf8(&resp).expect("valid utf8");
        assert!(text.contains("status=\"200\""));
        assert!(text.contains("<version>22.5</version>"));
    }

    #[test]
    fn test_echo_create_task() {
        let resp = echo_response("create_task", "22.5");
        let text = std::str::from_utf8(&resp).expect("valid utf8");
        assert!(text.contains("status=\"201\""));
        assert!(text.contains("id=\""));
    }

    #[test]
    fn test_echo_get_tasks() {
        let resp = echo_response("get_tasks", "22.5");
        let text = std::str::from_utf8(&resp).expect("valid utf8");
        assert!(text.contains("status=\"200\""));
        assert!(text.contains("get_tasks_response"));
    }

    #[test]
    fn test_echo_unknown() {
        let resp = echo_response("nonexistent_command", "22.5");
        let text = std::str::from_utf8(&resp).expect("valid utf8");
        assert!(text.contains("status=\"400\""));
    }

    #[test]
    fn test_error_response() {
        let resp = error_response("get_tasks", 404, "Not Found");
        let text = std::str::from_utf8(&resp).expect("valid utf8");
        assert!(text.contains("status=\"404\""));
        assert!(text.contains("Not Found"));
    }

    #[test]
    fn large_report_config_defaults_match_spec() {
        let config = LargeReportConfig::default();
        assert_eq!(config.result_count, 1_000);
        assert_eq!(config.result_payload_bytes, 512);
    }

    #[test]
    fn generate_large_report_small_payload_is_valid_xml() {
        let xml = generate_large_report(
            Uuid::parse_str("11111111-1111-1111-1111-111111111111").expect("valid uuid"),
            &LargeReportConfig {
                result_count: 10,
                result_payload_bytes: 64,
            },
        );

        let mut reader = Reader::from_str(&xml);
        loop {
            match reader.read_event() {
                Ok(Event::Eof) => break,
                Ok(_) => {}
                Err(error) => panic!("large report should be valid xml: {error}"),
            }
        }

        assert!(xml.contains("<get_reports_response"));
        assert!(xml.contains("<results max=\"10\" start=\"1\">"));
        assert!(xml.contains("<result_count><full>10</full><filtered>10</filtered></result_count>"));
    }

    #[test]
    fn generate_large_report_is_deterministic() {
        let report_id =
            Uuid::parse_str("22222222-2222-2222-2222-222222222222").expect("valid uuid");
        let config = LargeReportConfig {
            result_count: 10,
            result_payload_bytes: 32,
        };

        let first = generate_large_report(report_id, &config);
        let second = generate_large_report(report_id, &config);
        assert_eq!(first, second);
    }

    #[test]
    fn generate_large_report_payload_size_is_approximate() {
        let config = LargeReportConfig {
            result_count: 10,
            result_payload_bytes: 256,
        };
        let xml = generate_large_report(
            Uuid::parse_str("33333333-3333-3333-3333-333333333333").expect("valid uuid"),
            &config,
        );
        let descriptions = extract_descriptions(&xml);
        let total_description_bytes: usize = descriptions.iter().map(String::len).sum();
        let expected = config.result_count * config.result_payload_bytes;
        let lower_bound = expected * 9 / 10;
        let upper_bound = expected * 11 / 10;

        assert_eq!(descriptions.len(), config.result_count);
        assert!(
            (lower_bound..=upper_bound).contains(&total_description_bytes),
            "description payload bytes {total_description_bytes} not within 10% of {expected}"
        );
    }

    #[test]
    fn generate_binary_report_export_contains_metadata() {
        let report_id =
            Uuid::parse_str("44444444-4444-4444-4444-444444444444").expect("valid uuid");
        let xml = generate_binary_report_export(report_id, REPORT_EXPORT_BINARY_FORMAT_ID);

        assert!(xml.contains("content_type=\"application/pdf\""));
        assert!(xml.contains("extension=\"pdf\""));
        assert!(xml.contains(REPORT_EXPORT_BINARY_BODY));
    }

    #[test]
    fn generate_xml_report_export_contains_nested_report() {
        let report_id =
            Uuid::parse_str("55555555-5555-5555-5555-555555555555").expect("valid uuid");
        let xml = generate_xml_report_export(report_id, REPORT_EXPORT_XML_FORMAT_ID);

        assert!(xml.contains("content_type=\"text/xml\""));
        assert!(xml.contains("extension=\"xml\""));
        assert!(xml.contains(r#"<report id="55555555-5555-5555-5555-555555555555"><results>"#));
    }
}
