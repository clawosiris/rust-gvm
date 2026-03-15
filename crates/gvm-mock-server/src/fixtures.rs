// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Fixture library for realistic GMP responses.

use std::collections::HashMap;

use crate::util::now_iso;
use crate::version::GmpVersion;

/// Built-in fixture store.
#[derive(Debug, Clone)]
pub struct FixtureStore {
    /// Fixtures keyed by command name (e.g., "get_tasks").
    fixtures: HashMap<String, String>,
    version: GmpVersion,
}

impl FixtureStore {
    /// Create a new fixture store for the given version.
    pub fn new(version: GmpVersion) -> Self {
        let mut store = Self {
            fixtures: HashMap::new(),
            version,
        };
        store.load_builtins();
        store
    }

    /// Look up a fixture response for a command.
    pub fn get(&self, command_name: &str) -> Option<String> {
        // Try version-specific first, then common
        let version_key = format!("{}/{command_name}", self.version.as_str());
        if let Some(fixture) = self.fixtures.get(&version_key) {
            return Some(self.substitute_variables(fixture));
        }
        if let Some(fixture) = self.fixtures.get(command_name) {
            return Some(self.substitute_variables(fixture));
        }
        None
    }

    /// Add or override a fixture.
    pub fn insert(&mut self, command_name: &str, xml: &str) {
        self.fixtures
            .insert(command_name.to_string(), xml.to_string());
    }

    fn substitute_variables(&self, template: &str) -> String {
        let now = now_iso();
        template
            .replace("{{uuid}}", &uuid::Uuid::new_v4().to_string())
            .replace("{{now}}", &now)
            .replace("{{version}}", self.version.as_str())
    }

    fn load_builtins(&mut self) {
        // get_version
        self.fixtures.insert(
            "get_version".to_string(),
            format!(
                "<get_version_response status=\"200\" status_text=\"OK\">\
                 <version>{{{{version}}}}</version>\
                 </get_version_response>"
            ),
        );

        // authenticate (success)
        self.fixtures.insert(
            "authenticate".to_string(),
            "<authenticate_response status=\"200\" status_text=\"OK\">\
             <role>Admin</role>\
             <timezone>UTC</timezone>\
             </authenticate_response>"
                .to_string(),
        );

        // get_tasks (multiple)
        self.fixtures.insert(
            "get_tasks".to_string(),
            "<get_tasks_response status=\"200\" status_text=\"OK\">\
             <task id=\"{{uuid}}\">\
             <name>Discovery Scan</name>\
             <comment>Automated network discovery</comment>\
             <status>Done</status>\
             <creation_time>{{now}}</creation_time>\
             <modification_time>{{now}}</modification_time>\
             </task>\
             <task id=\"{{uuid}}\">\
             <name>Full Audit</name>\
             <comment>Complete vulnerability audit</comment>\
             <status>New</status>\
             <creation_time>{{now}}</creation_time>\
             <modification_time>{{now}}</modification_time>\
             </task>\
             <task_count>2<filtered>2</filtered></task_count>\
             </get_tasks_response>"
                .to_string(),
        );

        // create_task
        self.fixtures.insert(
            "create_task".to_string(),
            "<create_task_response status=\"201\" \
             status_text=\"OK, resource created\" \
             id=\"{{uuid}}\"/>"
                .to_string(),
        );

        // get_targets
        self.fixtures.insert(
            "get_targets".to_string(),
            "<get_targets_response status=\"200\" status_text=\"OK\">\
             <target id=\"{{uuid}}\">\
             <name>Local Network</name>\
             <hosts>192.168.1.0/24</hosts>\
             <creation_time>{{now}}</creation_time>\
             <modification_time>{{now}}</modification_time>\
             </target>\
             <target_count>1<filtered>1</filtered></target_count>\
             </get_targets_response>"
                .to_string(),
        );

        // create_target
        self.fixtures.insert(
            "create_target".to_string(),
            "<create_target_response status=\"201\" \
             status_text=\"OK, resource created\" \
             id=\"{{uuid}}\"/>"
                .to_string(),
        );

        // get_configs
        self.fixtures.insert(
            "get_configs".to_string(),
            "<get_configs_response status=\"200\" status_text=\"OK\">\
             <config id=\"{{uuid}}\">\
             <name>Full and fast</name>\
             <comment>Most NVT families enabled</comment>\
             <creation_time>{{now}}</creation_time>\
             <modification_time>{{now}}</modification_time>\
             </config>\
             <config_count>1<filtered>1</filtered></config_count>\
             </get_configs_response>"
                .to_string(),
        );

        // get_scanners
        self.fixtures.insert(
            "get_scanners".to_string(),
            "<get_scanners_response status=\"200\" status_text=\"OK\">\
             <scanner id=\"{{uuid}}\">\
             <name>OpenVAS Default</name>\
             <type>2</type>\
             <creation_time>{{now}}</creation_time>\
             <modification_time>{{now}}</modification_time>\
             </scanner>\
             <scanner_count>1<filtered>1</filtered></scanner_count>\
             </get_scanners_response>"
                .to_string(),
        );

        // help
        self.fixtures.insert(
            "help".to_string(),
            "<help_response status=\"200\" status_text=\"OK\">\
             <schema format=\"XML\"/>\
             </help_response>"
                .to_string(),
        );

        // get_alerts
        self.fixtures.insert(
            "get_alerts".to_string(),
            "<get_alerts_response status=\"200\" status_text=\"OK\">\
             <alert id=\"{{uuid}}\">\
             <name>Email Alert</name>\
             <condition>Severity at least</condition>\
             <event>Task run status changed</event>\
             <method>Email</method>\
             <creation_time>{{now}}</creation_time>\
             <modification_time>{{now}}</modification_time>\
             </alert>\
             <alert id=\"{{uuid}}\">\
             <name>Syslog Alert</name>\
             <condition>Always</condition>\
             <event>Updated SecInfo arrived</event>\
             <method>SysLog</method>\
             <creation_time>{{now}}</creation_time>\
             <modification_time>{{now}}</modification_time>\
             </alert>\
             <alert_count>2<filtered>2</filtered></alert_count>\
             </get_alerts_response>"
                .to_string(),
        );

        // create_alert
        self.fixtures.insert(
            "create_alert".to_string(),
            "<create_alert_response status=\"201\" \
             status_text=\"OK, resource created\" \
             id=\"{{uuid}}\"/>"
                .to_string(),
        );

        // get_credentials
        self.fixtures.insert(
            "get_credentials".to_string(),
            "<get_credentials_response status=\"200\" status_text=\"OK\">\
             <credential id=\"{{uuid}}\">\
             <name>SSH Key</name>\
             <type>usk</type>\
             <login>scanner</login>\
             <creation_time>{{now}}</creation_time>\
             <modification_time>{{now}}</modification_time>\
             </credential>\
             <credential_count>1<filtered>1</filtered></credential_count>\
             </get_credentials_response>"
                .to_string(),
        );

        // create_credential
        self.fixtures.insert(
            "create_credential".to_string(),
            "<create_credential_response status=\"201\" \
             status_text=\"OK, resource created\" \
             id=\"{{uuid}}\"/>"
                .to_string(),
        );

        // get_filters
        self.fixtures.insert(
            "get_filters".to_string(),
            "<get_filters_response status=\"200\" status_text=\"OK\">\
             <filter id=\"{{uuid}}\">\
             <name>High Severity</name>\
             <type>result</type>\
             <term>severity>7</term>\
             <creation_time>{{now}}</creation_time>\
             <modification_time>{{now}}</modification_time>\
             </filter>\
             <filter_count>1<filtered>1</filtered></filter_count>\
             </get_filters_response>"
                .to_string(),
        );

        // get_notes
        self.fixtures.insert(
            "get_notes".to_string(),
            "<get_notes_response status=\"200\" status_text=\"OK\">\
             <note id=\"{{uuid}}\">\
             <text>False positive on internal scanner</text>\
             <nvt oid=\"1.3.6.1.4.1.25623.1.0.100315\"><name>Test NVT</name></nvt>\
             <creation_time>{{now}}</creation_time>\
             <modification_time>{{now}}</modification_time>\
             </note>\
             <note_count>1<filtered>1</filtered></note_count>\
             </get_notes_response>"
                .to_string(),
        );

        // get_overrides
        self.fixtures.insert(
            "get_overrides".to_string(),
            "<get_overrides_response status=\"200\" status_text=\"OK\">\
             <override id=\"{{uuid}}\">\
             <text>Downgrade to log</text>\
             <nvt oid=\"1.3.6.1.4.1.25623.1.0.100315\"><name>Test NVT</name></nvt>\
             <new_severity>0.0</new_severity>\
             <creation_time>{{now}}</creation_time>\
             <modification_time>{{now}}</modification_time>\
             </override>\
             <override_count>1<filtered>1</filtered></override_count>\
             </get_overrides_response>"
                .to_string(),
        );

        // get_schedules
        self.fixtures.insert(
            "get_schedules".to_string(),
            "<get_schedules_response status=\"200\" status_text=\"OK\">\
             <schedule id=\"{{uuid}}\">\
             <name>Weekly Scan</name>\
             <icalendar>BEGIN:VCALENDAR\nEND:VCALENDAR</icalendar>\
             <creation_time>{{now}}</creation_time>\
             <modification_time>{{now}}</modification_time>\
             </schedule>\
             <schedule_count>1<filtered>1</filtered></schedule_count>\
             </get_schedules_response>"
                .to_string(),
        );

        // get_reports
        self.fixtures.insert(
            "get_reports".to_string(),
            "<get_reports_response status=\"200\" status_text=\"OK\">\
             <report id=\"{{uuid}}\">\
             <task id=\"{{uuid}}\"><name>Scan Task</name></task>\
             <result_count>42<filtered>42</filtered></result_count>\
             <creation_time>{{now}}</creation_time>\
             <modification_time>{{now}}</modification_time>\
             </report>\
             <report_count>1<filtered>1</filtered></report_count>\
             </get_reports_response>"
                .to_string(),
        );

        // get_port_lists
        self.fixtures.insert(
            "get_port_lists".to_string(),
            "<get_port_lists_response status=\"200\" status_text=\"OK\">\
             <port_list id=\"{{uuid}}\">\
             <name>All IANA TCP</name>\
             <port_count>65535</port_count>\
             <creation_time>{{now}}</creation_time>\
             <modification_time>{{now}}</modification_time>\
             </port_list>\
             <port_list_count>1<filtered>1</filtered></port_list_count>\
             </get_port_lists_response>"
                .to_string(),
        );

        // get_roles
        self.fixtures.insert(
            "get_roles".to_string(),
            "<get_roles_response status=\"200\" status_text=\"OK\">\
             <role id=\"{{uuid}}\">\
             <name>Admin</name>\
             <creation_time>{{now}}</creation_time>\
             <modification_time>{{now}}</modification_time>\
             </role>\
             <role_count>1<filtered>1</filtered></role_count>\
             </get_roles_response>"
                .to_string(),
        );

        // get_users
        self.fixtures.insert(
            "get_users".to_string(),
            "<get_users_response status=\"200\" status_text=\"OK\">\
             <user id=\"{{uuid}}\">\
             <name>admin</name>\
             <role id=\"{{uuid}}\"><name>Admin</name></role>\
             <creation_time>{{now}}</creation_time>\
             <modification_time>{{now}}</modification_time>\
             </user>\
             <user_count>1<filtered>1</filtered></user_count>\
             </get_users_response>"
                .to_string(),
        );

        // get_tickets
        self.fixtures.insert(
            "get_tickets".to_string(),
            "<get_tickets_response status=\"200\" status_text=\"OK\">\
             <ticket id=\"{{uuid}}\">\
             <name>Fix CVE-2024-1234</name>\
             <status>Open</status>\
             <creation_time>{{now}}</creation_time>\
             <modification_time>{{now}}</modification_time>\
             </ticket>\
             <ticket_count>1<filtered>1</filtered></ticket_count>\
             </get_tickets_response>"
                .to_string(),
        );

        // get_tags
        self.fixtures.insert(
            "get_tags".to_string(),
            "<get_tags_response status=\"200\" status_text=\"OK\">\
             <tag id=\"{{uuid}}\">\
             <name>environment:production</name>\
             <value>true</value>\
             <creation_time>{{now}}</creation_time>\
             <modification_time>{{now}}</modification_time>\
             </tag>\
             <tag_count>1<filtered>1</filtered></tag_count>\
             </get_tags_response>"
                .to_string(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixture_get_version() {
        let store = FixtureStore::new(GmpVersion::V22_5);
        let fixture = store.get("get_version").expect("should have fixture");
        assert!(fixture.contains("22.5"));
        assert!(fixture.contains("status=\"200\""));
    }

    #[test]
    fn test_fixture_authenticate() {
        let store = FixtureStore::new(GmpVersion::V22_5);
        let fixture = store.get("authenticate").expect("should have fixture");
        assert!(fixture.contains("Admin"));
        assert!(fixture.contains("UTC"));
    }

    #[test]
    fn test_fixture_get_tasks() {
        let store = FixtureStore::new(GmpVersion::V22_5);
        let fixture = store.get("get_tasks").expect("should have fixture");
        assert!(fixture.contains("Discovery Scan"));
        assert!(fixture.contains("task_count"));
    }

    #[test]
    fn test_fixture_uuid_substitution() {
        let store = FixtureStore::new(GmpVersion::V22_5);
        let f1 = store.get("create_task").expect("should have fixture");
        let f2 = store.get("create_task").expect("should have fixture");
        // UUIDs should be different each time
        assert_ne!(f1, f2);
    }

    #[test]
    fn test_fixture_missing() {
        let store = FixtureStore::new(GmpVersion::V22_5);
        assert!(store.get("nonexistent_command").is_none());
    }

    #[test]
    fn test_fixture_override() {
        let mut store = FixtureStore::new(GmpVersion::V22_5);
        store.insert(
            "get_tasks",
            "<get_tasks_response status=\"200\" status_text=\"OK\"/>",
        );
        let fixture = store.get("get_tasks").expect("should have fixture");
        assert!(!fixture.contains("Discovery Scan")); // overridden
    }
}
