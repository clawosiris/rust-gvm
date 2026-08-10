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
             <commands><command>get_feeds</command><command>get_tasks</command><command>get_configs</command></commands>\
             </help_response>"
                .to_string(),
        );

        // get_feeds
        self.fixtures.insert(
            "get_feeds".to_string(),
            "<get_feeds_response status=\"200\" status_text=\"OK\">\
             <feed><type>NVT</type><name>Network Vulnerability Tests</name><version>2026031801</version><status>current</status></feed>\
             <feed><type>SCAP</type><name>SCAP Data</name><version>2026031701</version><status>current</status></feed>\
             <feed><type>CERT</type><name>CERT Advisories</name><version>2026031601</version><status>current</status></feed>\
             <feed_count>3<filtered>3</filtered></feed_count>\
             </get_feeds_response>"
                .to_string(),
        );

        // get_aggregates
        self.fixtures.insert(
            "get_aggregates".to_string(),
            "<get_aggregates_response status=\"200\" status_text=\"OK\">\
             <aggregate><data_type>task</data_type><group_column>severity</group_column>\
             <group><value>High</value><count>3</count><c_count>3</c_count></group>\
             <group><value>Medium</value><count>5</count><c_count>8</c_count></group>\
             <column_info><aggregate_column><name>value</name><stat>value</stat>\
             <type>task</type><column>severity</column><data_type>text</data_type>\
             </aggregate_column></column_info></aggregate>\
             <filters id=\"\"><term></term><keywords/></filters>\
             </get_aggregates_response>"
                .to_string(),
        );

        // get_system_reports
        self.fixtures.insert(
            "get_system_reports".to_string(),
            "<get_system_reports_response status=\"200\" status_text=\"OK\">\
             <system_report id=\"system-report-1\">\
             <name>GVMD Performance Snapshot</name>\
             <comment>Mock system report</comment>\
             </system_report>\
             <system_report_count>1<filtered>1</filtered></system_report_count>\
             </get_system_reports_response>"
                .to_string(),
        );

        // get_info
        self.fixtures.insert(
            "get_info".to_string(),
            "<get_info_response status=\"200\" status_text=\"OK\">\
             <cve id=\"CVE-2026-1000\"><name>Mock CVE one</name></cve>\
             <cve id=\"CVE-2026-1001\"><name>Mock CVE two</name></cve>\
             <cve_count>2<filtered>2</filtered></cve_count>\
             </get_info_response>"
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

        // get_credential_stores
        self.fixtures.insert(
            "get_credential_stores".to_string(),
            "<get_credential_stores_response status=\"200\" status_text=\"OK\">\
             <credential_store id=\"local\"><name>Local credential store</name><type>local</type></credential_store>\
             <credential_store_count>1<filtered>1</filtered></credential_store_count>\
             </get_credential_stores_response>"
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
             <icalendar>BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\nDTSTART:20300101T000000Z\nRRULE:FREQ=WEEKLY\nEND:VEVENT\nEND:VCALENDAR</icalendar>\
             <timezone>UTC</timezone>\
             <first_run>2030-01-01T00:00:00Z</first_run>\
             <next_run>2030-01-01T00:00:00Z</next_run>\
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

        // report drill-down helpers
        self.fixtures.insert(
            "get_report_vulns".to_string(),
            "<get_report_vulns_response status=\"200\" status_text=\"OK\">\
             <vulns><vuln><nvt oid=\"1.3.6.1.4.1.25623.1.0.117761\"><name>SSL/TLS Renegotiation Vulnerability</name></nvt><cves><cve>CVE-2011-1473</cve><cve>CVE-2011-5094</cve></cves><hosts_count>2</hosts_count><occurrences>3</occurrences><severity>5.0</severity><threat>Medium</threat></vuln></vulns>\
             <report_vuln_count>1<filtered>1</filtered></report_vuln_count>\
             </get_report_vulns_response>"
                .to_string(),
        );
        self.fixtures.insert(
            "get_report_tls_certificates".to_string(),
            "<get_report_tls_certificates_response status=\"200\" status_text=\"OK\">\
             <tls_certificate id=\"tls-1\"><name>example.com</name><host>192.0.2.10</host><port>443/tcp</port><subject>CN=example.com</subject><issuer>CN=Example CA</issuer><serial>01</serial><expiration_time>2027-01-01T00:00:00Z</expiration_time></tls_certificate>\
             <tls_certificate_count>1<filtered>1</filtered></tls_certificate_count>\
             </get_report_tls_certificates_response>"
                .to_string(),
        );
        self.fixtures.insert(
            "get_report_errors".to_string(),
            "<get_report_errors_response status=\"200\" status_text=\"OK\">\
             <error id=\"err-1\"><name>Host dead</name><host>192.0.2.20</host><port>general/tcp</port><description>Could not reach host.</description><nvt><name>Ping Host</name></nvt></error>\
             <error_count>1<filtered>1</filtered></error_count>\
             </get_report_errors_response>"
                .to_string(),
        );
        self.fixtures.insert(
            "get_report_closed_cves".to_string(),
            "<get_report_closed_cves_response status=\"200\" status_text=\"OK\">\
             <closed_cves><closed_cve><host>192.0.2.30</host><cve>CVE-2025-9999</cve><nvt oid=\"1.3.6.1.4.1.25623.1.0.100000\"><name>Closed vulnerability check</name></nvt><severity>5.0</severity><threat>Medium</threat></closed_cve></closed_cves>\
             <report_closed_cve_count>1<filtered>1</filtered></report_closed_cve_count>\
             </get_report_closed_cves_response>"
                .to_string(),
        );

        // get_timezones
        self.fixtures.insert(
            "get_timezones".to_string(),
            "<get_timezones_response status=\"200\" status_text=\"OK\">\
             <timezone>UTC</timezone><timezone><name>Europe/Berlin</name><offset>+01:00</offset></timezone>\
             </get_timezones_response>"
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
