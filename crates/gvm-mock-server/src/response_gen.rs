//! GMP response XML generation.

use uuid::Uuid;

use crate::util::xml_escape_attr;

/// Known GMP commands that the mock server recognizes.
pub static KNOWN_COMMANDS: &[&str] = &[
    "authenticate",
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
    "get_aggregates",
    "get_alerts",
    "get_assets",
    "get_configs",
    "get_credentials",
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
