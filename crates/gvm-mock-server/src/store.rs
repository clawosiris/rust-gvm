// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! In-memory resource store for Stateful mode.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use uuid::Uuid;

use crate::util::{now_iso, xml_escape, xml_escape_attr};

/// Input profile for stateful asset commands.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AssetInputProfile {
    /// Require the asset command shapes accepted by current gvmd.
    #[default]
    GvmdStrict,
    /// Accept the historical flat mock inputs (`asset_type`, `<asset_type>`, and `<value>`).
    ///
    /// This profile exists only for consumers that explicitly need compatibility
    /// with the mock's former, non-canonical asset command surface.
    LegacyFlatCompatibility,
}

/// Task status in the lifecycle state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskStatus {
    /// Newly created, not yet started.
    New,
    /// Start requested.
    Requested,
    /// Currently running.
    Running,
    /// Stop requested.
    StopRequested,
    /// Stopped by user.
    Stopped,
    /// Completed successfully.
    Done,
}

impl TaskStatus {
    /// Return the GMP status string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "New",
            Self::Requested => "Requested",
            Self::Running => "Running",
            Self::StopRequested => "Stop Requested",
            Self::Stopped => "Stopped",
            Self::Done => "Done",
        }
    }
}

/// A stored GMP resource (generic for all resource types).
#[derive(Debug, Clone)]
pub struct Resource {
    /// Resource UUID.
    pub id: Uuid,
    /// Resource type name (e.g., "task", "target").
    pub resource_type: String,
    /// Resource name.
    pub name: String,
    /// Optional comment.
    pub comment: String,
    /// Creation timestamp (ISO 8601).
    pub creation_time: String,
    /// Modification timestamp (ISO 8601).
    pub modification_time: String,
    /// Additional type-specific attributes.
    pub attrs: BTreeMap<String, String>,
    /// Whether this resource is in the trashcan.
    pub trashed: bool,
}

impl Resource {
    /// Create a new resource with auto-generated UUID and timestamps.
    pub fn new(resource_type: &str, name: &str) -> Self {
        let now = now_iso();
        Self {
            id: Uuid::new_v4(),
            resource_type: resource_type.to_string(),
            name: name.to_string(),
            comment: String::new(),
            creation_time: now.clone(),
            modification_time: now,
            attrs: BTreeMap::new(),
            trashed: false,
        }
    }

    /// Create with a specific UUID.
    pub fn with_id(resource_type: &str, name: &str, id: Uuid) -> Self {
        let mut r = Self::new(resource_type, name);
        r.id = id;
        r
    }

    /// Set an attribute.
    pub fn set_attr(&mut self, key: &str, value: &str) {
        self.attrs.insert(key.to_string(), value.to_string());
    }

    /// Get an attribute.
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attrs.get(key).map(String::as_str)
    }

    /// Return the canonical asset type, including legacy seeded resources.
    pub(crate) fn asset_type(&self) -> Option<&str> {
        self.attr("type").or_else(|| self.attr("asset_type"))
    }

    /// Generate the canonical gvmd asset representation used by `get_assets`.
    pub(crate) fn to_asset_xml(&self) -> String {
        let asset_type = self.asset_type().unwrap_or_default();
        let writable = if asset_type == "os" { "0" } else { "1" };
        let in_use = if asset_type == "os"
            && self
                .attr("installs")
                .and_then(|value| value.parse::<u32>().ok())
                .is_some_and(|count| count > 0)
        {
            "1"
        } else {
            "0"
        };
        let common = format!(
            "<asset id=\"{id}\">\
             <owner><name>admin</name></owner>\
             <name>{name}</name>\
             <comment>{comment}</comment>\
             <creation_time>{ct}</creation_time>\
             <modification_time>{mt}</modification_time>\
             <writable>{writable}</writable>\
             <in_use>{in_use}</in_use>\
             <permissions><permission><name>Everything</name></permission></permissions>",
            id = self.id,
            name = xml_escape(&self.name),
            comment = xml_escape(&self.comment),
            ct = self.creation_time,
            mt = self.modification_time,
            writable = writable,
            in_use = in_use,
        );

        match asset_type {
            "host" => {
                let severity = self.attr("severity").unwrap_or_default();
                format!(
                    "{common}\
                     <identifiers><identifier id=\"{id}\">\
                     <name>ip</name><value>{name}</value>\
                     <creation_time>{ct}</creation_time>\
                     <modification_time>{mt}</modification_time>\
                     <source><type>User</type><data></data><deleted>0</deleted><name>admin</name></source>\
                     </identifier></identifiers>\
                     <type>host</type>\
                     <host><severity><value>{severity}</value></severity></host>\
                     </asset>",
                    id = self.id,
                    name = xml_escape(&self.name),
                    ct = self.creation_time,
                    mt = self.modification_time,
                    severity = xml_escape(severity),
                )
            }
            "os" => {
                let title = self.attr("title").unwrap_or(&self.name);
                let installs = self.attr("installs").unwrap_or("0");
                let all_installs = self.attr("all_installs").unwrap_or(installs);
                let latest = self.attr("latest_severity").unwrap_or_default();
                let highest = self.attr("highest_severity").unwrap_or_default();
                let average = self.attr("average_severity").unwrap_or_default();
                format!(
                    "{common}\
                     <type>os</type>\
                     <os>\
                     <latest_severity><value>{latest}</value></latest_severity>\
                     <highest_severity><value>{highest}</value></highest_severity>\
                     <average_severity><value>{average}</value></average_severity>\
                     <title>{title}</title>\
                     <installs>{installs}</installs>\
                     <all_installs>{all_installs}</all_installs>\
                     <hosts>{installs}</hosts>\
                     </os>\
                     </asset>",
                    latest = xml_escape(latest),
                    highest = xml_escape(highest),
                    average = xml_escape(average),
                    title = xml_escape(title),
                    installs = xml_escape(installs),
                    all_installs = xml_escape(all_installs),
                )
            }
            _ => format!("{common}<type>{}</type></asset>", xml_escape(asset_type)),
        }
    }

    /// Generate XML representation for get responses.
    pub fn to_xml(&self) -> String {
        // Notes and overrides use <text> instead of <name>
        let name_tag = if self.resource_type == "note" || self.resource_type == "override" {
            "text"
        } else {
            "name"
        };
        let oid_attr = if self.resource_type == "nvt" {
            self.attr("oid")
                .or_else(|| self.attr("nvt_oid"))
                .map(|oid| format!(" oid=\"{}\"", xml_escape_attr(oid)))
                .unwrap_or_default()
        } else {
            String::new()
        };
        let mut xml = format!(
            "<{type} id=\"{id}\"{oid_attr}>\
             <{name_tag}>{name}</{name_tag}>\
             <comment>{comment}</comment>\
             <creation_time>{ct}</creation_time>\
             <modification_time>{mt}</modification_time>",
            type = self.resource_type,
            id = self.id,
            oid_attr = oid_attr,
            name_tag = name_tag,
            name = xml_escape(&self.name),
            comment = xml_escape(&self.comment),
            ct = self.creation_time,
            mt = self.modification_time,
        );
        // Add type-specific attributes
        for (k, v) in &self.attrs {
            if self.resource_type == "nvt"
                && matches!(
                    k.as_str(),
                    "oid" | "nvt_oid" | "config_id" | "preferences_config_id"
                )
            {
                continue;
            }
            xml.push_str(&format!("<{k}>{}</{k}>", xml_escape(v)));
        }
        xml.push_str(&format!("</{}>", self.resource_type));
        xml
    }
}

/// Thread-safe resource store.
#[derive(Debug, Clone)]
pub struct ResourceStore {
    inner: Arc<RwLock<StoreInner>>,
}

#[derive(Debug)]
struct StoreInner {
    resources: HashMap<Uuid, Resource>,
    /// Stateful asset request parsing profile.
    asset_input_profile: AssetInputProfile,
    /// Authenticated sessions.
    authenticated_sessions: std::collections::HashSet<u64>,
    /// Configured credentials.
    username: String,
    password: String,
}

fn default_resources() -> HashMap<Uuid, Resource> {
    let mut resources = HashMap::new();

    let mut timezone = Resource::with_id(
        "setting",
        "timezone",
        Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("valid uuid"),
    );
    timezone.comment = "User timezone".to_string();
    timezone.set_attr("value", "UTC");
    resources.insert(timezone.id, timezone);

    let mut rows_per_page = Resource::with_id(
        "setting",
        "rows_per_page",
        Uuid::parse_str("00000000-0000-0000-0000-000000000002").expect("valid uuid"),
    );
    rows_per_page.comment = "Default rows per page".to_string();
    rows_per_page.set_attr("value", "100");
    resources.insert(rows_per_page.id, rows_per_page);

    let mut integration_config = Resource::with_id(
        "integration_config",
        "Default Integration Config",
        Uuid::parse_str("00000000-0000-0000-0000-000000000100").expect("valid uuid"),
    );
    integration_config.comment = "Mock integration config".to_string();
    integration_config.set_attr("service_url", "https://service.example.invalid");
    integration_config.set_attr("service_cacert", "MOCK-CA-CERT");
    integration_config.set_attr("oidc_provider_url", "https://oidc.example.invalid");
    integration_config.set_attr("oidc_provider_client_id", "mock-client-id");
    integration_config.set_attr("oidc_provider_client_secret", "mock-client-secret");
    resources.insert(integration_config.id, integration_config);

    resources
}

impl ResourceStore {
    /// Create a new empty store with default credentials.
    pub fn new() -> Self {
        Self::with_credentials("admin", "admin")
    }

    /// Create a store with specific credentials.
    pub fn with_credentials(username: &str, password: &str) -> Self {
        Self {
            inner: Arc::new(RwLock::new(StoreInner {
                resources: default_resources(),
                asset_input_profile: AssetInputProfile::GvmdStrict,
                authenticated_sessions: std::collections::HashSet::new(),
                username: username.to_string(),
                password: password.to_string(),
            })),
        }
    }

    /// Authenticate a session. Returns true if credentials are valid.
    pub fn authenticate(&self, session_id: u64, username: &str, password: &str) -> bool {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if inner.username == username && inner.password == password {
            inner.authenticated_sessions.insert(session_id);
            true
        } else {
            false
        }
    }

    /// Check if a session is authenticated.
    pub fn is_authenticated(&self, session_id: u64) -> bool {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.authenticated_sessions.contains(&session_id)
    }

    /// Set the asset request parsing profile before the server starts.
    pub(crate) fn set_asset_input_profile(&self, profile: AssetInputProfile) {
        let mut inner = self.inner.write().expect("store lock poisoned");
        inner.asset_input_profile = profile;
    }

    /// Return the configured asset request parsing profile.
    pub(crate) fn asset_input_profile(&self) -> AssetInputProfile {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.asset_input_profile
    }

    /// Check whether the provided credentials match the configured SSH credentials.
    #[cfg(feature = "ssh")]
    pub(crate) fn credentials_match(&self, username: &str, password: &str) -> bool {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.username == username && inner.password == password
    }

    /// Create a resource. Returns the generated UUID.
    pub fn create(&self, mut resource: Resource) -> Uuid {
        let id = resource.id;
        resource.modification_time = now_iso();
        let mut inner = self.inner.write().expect("store lock poisoned");
        inner.resources.insert(id, resource);
        id
    }

    /// Get a resource by UUID.
    pub fn get(&self, id: &Uuid) -> Option<Resource> {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.resources.get(id).filter(|r| !r.trashed).cloned()
    }

    /// Get all resources of a given type (non-trashed).
    pub fn list(&self, resource_type: &str) -> Vec<Resource> {
        let inner = self.inner.read().expect("store lock poisoned");
        inner
            .resources
            .values()
            .filter(|r| r.resource_type == resource_type && !r.trashed)
            .cloned()
            .collect()
    }

    /// Get all trashed resources of a given type.
    pub fn list_trashed(&self, resource_type: &str) -> Vec<Resource> {
        let inner = self.inner.read().expect("store lock poisoned");
        inner
            .resources
            .values()
            .filter(|r| r.resource_type == resource_type && r.trashed)
            .cloned()
            .collect()
    }

    /// Modify a resource. Returns true if found and updated.
    pub fn modify<F>(&self, id: &Uuid, f: F) -> bool
    where
        F: FnOnce(&mut Resource),
    {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if let Some(resource) = inner.resources.get_mut(id) {
            if resource.trashed {
                return false;
            }
            f(resource);
            resource.modification_time = now_iso();
            true
        } else {
            false
        }
    }

    /// Modify the comment of a non-trashed host asset.
    pub(crate) fn modify_host_asset_comment(&self, id: &Uuid, comment: &str) -> bool {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let Some(resource) = inner.resources.get_mut(id) else {
            return false;
        };
        if resource.trashed
            || resource.resource_type != "asset"
            || resource.asset_type() != Some("host")
        {
            return false;
        }
        comment.clone_into(&mut resource.comment);
        resource.modification_time = now_iso();
        true
    }

    /// Delete a resource (move to trash or permanently).
    pub fn delete(&self, id: &Uuid, ultimate: bool) -> bool {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if ultimate {
            inner.resources.remove(id).is_some()
        } else if let Some(resource) = inner.resources.get_mut(id) {
            resource.trashed = true;
            true
        } else {
            false
        }
    }

    /// Permanently delete a non-trashed resource only when its type matches.
    pub(crate) fn delete_permanently_if_type(&self, id: &Uuid, resource_type: &str) -> bool {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let matches = inner
            .resources
            .get(id)
            .is_some_and(|resource| resource.resource_type == resource_type && !resource.trashed);
        matches && inner.resources.remove(id).is_some()
    }

    /// Restore a trashed resource.
    pub fn restore(&self, id: &Uuid) -> bool {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if let Some(resource) = inner.resources.get_mut(id) {
            if resource.trashed {
                resource.trashed = false;
                return true;
            }
        }
        false
    }

    /// Empty the trashcan (permanently remove all trashed resources).
    pub fn empty_trashcan(&self) {
        let mut inner = self.inner.write().expect("store lock poisoned");
        inner.resources.retain(|_, r| !r.trashed);
    }

    /// Clone a resource (create a copy with a new UUID).
    pub fn clone_resource(&self, id: &Uuid) -> Option<Uuid> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let original = inner.resources.get(id)?.clone();
        if original.trashed {
            return None;
        }

        let mut copy = original;
        copy.id = Uuid::new_v4();
        let now = now_iso();
        copy.creation_time = now.clone();
        copy.modification_time = now;
        let new_id = copy.id;
        inner.resources.insert(new_id, copy);
        Some(new_id)
    }

    /// List resources of a type, filtered by a simple `name=value` filter string.
    pub fn list_filtered(&self, resource_type: &str, filter: &str) -> Vec<Resource> {
        // Parse simple "name=value" filters (GMP filter syntax subset)
        let inner = self.inner.read().expect("store lock poisoned");
        let mut results: Vec<Resource> = inner
            .resources
            .values()
            .filter(|r| r.resource_type == resource_type && !r.trashed)
            .cloned()
            .collect();

        // Apply filter predicates
        for part in filter.split_whitespace() {
            if let Some((key, value)) = part.split_once('=') {
                match key {
                    "name" => {
                        results.retain(|r| r.name == value);
                    }
                    "type" => {
                        results.retain(|r| r.resource_type == value);
                    }
                    _ => {
                        // Check attrs
                        let key = key.to_string();
                        let value = value.to_string();
                        results.retain(|r| r.attr(&key) == Some(value.as_str()));
                    }
                }
            }
        }

        results
    }

    /// Count resources of a type (non-trashed).
    pub fn count(&self, resource_type: &str) -> usize {
        let inner = self.inner.read().expect("store lock poisoned");
        inner
            .resources
            .values()
            .filter(|r| r.resource_type == resource_type && !r.trashed)
            .count()
    }

    /// Seed a resource for testing.
    pub fn seed(&self, resource: Resource) {
        let mut resource = resource;
        resource.modification_time = now_iso();
        let mut inner = self.inner.write().expect("store lock poisoned");
        inner.resources.insert(resource.id, resource);
    }
}

impl Default for ResourceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn test_create_and_get() {
        let store = ResourceStore::new();
        let resource = Resource::new("task", "My Task");
        let id = store.create(resource);
        let fetched = store.get(&id).expect("should exist");
        assert_eq!(fetched.name, "My Task");
        assert_eq!(fetched.resource_type, "task");
    }

    #[test]
    fn test_list() {
        let store = ResourceStore::new();
        store.create(Resource::new("task", "Task 1"));
        store.create(Resource::new("task", "Task 2"));
        store.create(Resource::new("target", "Target 1"));

        assert_eq!(store.list("task").len(), 2);
        assert_eq!(store.list("target").len(), 1);
        assert_eq!(store.list("config").len(), 0);
    }

    #[test]
    fn test_modify() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Old Name"));
        let modified = store.modify(&id, |r| {
            r.name = "New Name".to_string();
        });
        assert!(modified);
        assert_eq!(store.get(&id).unwrap().name, "New Name");
    }

    #[test]
    fn test_delete_to_trash() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Doomed"));
        assert!(store.delete(&id, false));
        assert!(store.get(&id).is_none()); // hidden from normal get
        assert_eq!(store.list_trashed("task").len(), 1);
    }

    #[test]
    fn test_delete_ultimate() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Gone"));
        assert!(store.delete(&id, true));
        assert!(store.get(&id).is_none());
        assert_eq!(store.list_trashed("task").len(), 0);
    }

    #[test]
    fn test_restore() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Restored"));
        store.delete(&id, false);
        assert!(store.get(&id).is_none());
        assert!(store.restore(&id));
        assert!(store.get(&id).is_some());
    }

    #[test]
    fn test_empty_trashcan() {
        let store = ResourceStore::new();
        let id1 = store.create(Resource::new("task", "T1"));
        let id2 = store.create(Resource::new("task", "T2"));
        store.delete(&id1, false);
        store.delete(&id2, false);
        store.empty_trashcan();
        assert_eq!(store.list_trashed("task").len(), 0);
    }

    #[test]
    fn test_clone_resource() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Original"));
        let cloned_id = store.clone_resource(&id).expect("clone should work");
        assert_ne!(id, cloned_id);
        let original = store.get(&id).unwrap();
        let clone = store.get(&cloned_id).unwrap();
        assert_eq!(original.name, clone.name);
    }

    #[test]
    fn test_auth() {
        let store = ResourceStore::with_credentials("user", "pass");
        assert!(!store.is_authenticated(1));
        assert!(store.authenticate(1, "user", "pass"));
        assert!(store.is_authenticated(1));
        assert!(!store.authenticate(2, "user", "wrong"));
        assert!(!store.is_authenticated(2));
    }

    #[test]
    fn test_get_nonexistent() {
        let store = ResourceStore::new();
        assert!(store.get(&Uuid::new_v4()).is_none());
    }

    #[test]
    fn test_delete_nonexistent() {
        let store = ResourceStore::new();
        assert!(!store.delete(&Uuid::new_v4(), false));
    }

    #[test]
    fn test_list_filtered_by_name() {
        let store = ResourceStore::new();
        store.create(Resource::new("task", "Alpha"));
        store.create(Resource::new("task", "Beta"));
        store.create(Resource::new("task", "Alpha"));

        let filtered = store.list_filtered("task", "name=Alpha");
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|r| r.name == "Alpha"));
    }

    #[test]
    fn test_list_filtered_no_match() {
        let store = ResourceStore::new();
        store.create(Resource::new("task", "Alpha"));
        let filtered = store.list_filtered("task", "name=Nonexistent");
        assert_eq!(filtered.len(), 0);
    }

    #[test]
    fn test_list_filtered_by_attr() {
        let store = ResourceStore::new();
        let mut r = Resource::new("task", "T1");
        r.set_attr("status", "Running");
        store.create(r);
        let mut r2 = Resource::new("task", "T2");
        r2.set_attr("status", "New");
        store.create(r2);

        let filtered = store.list_filtered("task", "status=Running");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "T1");
    }

    #[test]
    fn test_count() {
        let store = ResourceStore::new();
        store.create(Resource::new("task", "T1"));
        store.create(Resource::new("task", "T2"));
        assert_eq!(store.count("task"), 2);
        assert_eq!(store.count("target"), 0);
    }

    #[test]
    fn test_modify_trashed_returns_false() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Trashed"));
        store.delete(&id, false);
        assert!(!store.modify(&id, |r| r.name = "New".to_string()));
    }

    #[test]
    fn test_clone_nonexistent() {
        let store = ResourceStore::new();
        assert!(store.clone_resource(&Uuid::new_v4()).is_none());
    }

    #[test]
    fn test_count_excludes_trashed() {
        let store = ResourceStore::new();
        store.create(Resource::new("task", "T1"));
        let id2 = store.create(Resource::new("task", "T2"));
        store.delete(&id2, false);
        assert_eq!(store.count("task"), 1);
    }

    #[test]
    fn test_list_filtered_multi_term() {
        let store = ResourceStore::new();
        let mut r = Resource::new("task", "Alpha");
        r.set_attr("status", "Running");
        store.create(r);
        let mut r2 = Resource::new("task", "Alpha");
        r2.set_attr("status", "New");
        store.create(r2);
        let filtered = store.list_filtered("task", "name=Alpha status=Running");
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_to_xml_sorts_attributes_deterministically() {
        let mut resource = Resource::new("task", "Ordered");
        resource.set_attr("zeta", "last");
        resource.set_attr("alpha", "first");

        let xml = resource.to_xml();

        assert!(xml.find("<alpha>").unwrap() < xml.find("<zeta>").unwrap());
    }

    #[test]
    fn test_clone_resource_stress_with_concurrent_deletes() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Original"));
        let barrier = Arc::new(Barrier::new(3));

        let clone_store = store.clone();
        let clone_barrier = Arc::clone(&barrier);
        let clone_thread = thread::spawn(move || {
            clone_barrier.wait();
            for _ in 0..250 {
                let _ = clone_store.clone_resource(&id);
                thread::yield_now();
            }
        });

        let delete_store = store.clone();
        let delete_barrier = Arc::clone(&barrier);
        let delete_thread = thread::spawn(move || {
            delete_barrier.wait();
            for _ in 0..250 {
                let _ = delete_store.delete(&id, false);
                let _ = delete_store.restore(&id);
                thread::yield_now();
            }
        });

        barrier.wait();
        clone_thread.join().expect("clone thread");
        delete_thread.join().expect("delete thread");

        let tasks = store.list("task");
        assert!(tasks
            .iter()
            .all(|resource| resource.resource_type == "task"));
        assert!(tasks.iter().any(|resource| resource.id == id));
    }
}
