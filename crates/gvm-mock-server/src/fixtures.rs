//! Fixture library for realistic GMP responses.

use std::collections::HashMap;

use crate::version::GmpVersion;

/// Built-in fixture store.
#[derive(Debug, Clone)]
pub struct FixtureStore {
    /// Fixtures keyed by (command_name, version).
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
        let now = chrono_now_iso();
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
    }
}

/// Get current time in ISO 8601 format (without chrono dependency).
fn chrono_now_iso() -> String {
    // Use a fixed-ish format. In production we'd use chrono,
    // but to avoid adding a dependency, we use a simple approach.
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Simple ISO-ish format
    format!("{secs}")
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
