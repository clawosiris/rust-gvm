#![allow(
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]

use gvm_mock_server::{Resource, ResourceStore};
use uuid::Uuid;

#[test]
fn crud_targets() {
    let store = ResourceStore::new();
    let id = store.create(Resource::new("target", "Initial Target"));

    let target = store.get(&id).expect("target should exist");
    assert_eq!(target.resource_type, "target");
    assert_eq!(target.name, "Initial Target");

    assert!(store.modify(&id, |resource| {
        resource.name = "Updated Target".to_string();
    }));
    assert_eq!(store.get(&id).unwrap().name, "Updated Target");

    assert!(store.delete(&id, true));
    assert!(store.get(&id).is_none());
}

#[test]
fn crud_configs() {
    let store = ResourceStore::new();
    let id = store.create(Resource::new("config", "Base Config"));

    let config = store.get(&id).expect("config should exist");
    assert_eq!(config.resource_type, "config");
    assert_eq!(config.name, "Base Config");

    let configs = store.list("config");
    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0].id, id);

    assert!(store.delete(&id, true));
    assert!(store.get(&id).is_none());
    assert!(store.list("config").is_empty());
}

#[test]
fn crud_scanners() {
    let store = ResourceStore::new();
    let id = store.create(Resource::new("scanner", "Primary Scanner"));

    let cloned_id = store
        .clone_resource(&id)
        .expect("scanner clone should succeed");

    assert_ne!(id, cloned_id);
    assert!(store.get(&id).is_some());
    assert!(store.get(&cloned_id).is_some());
    assert_eq!(store.list("scanner").len(), 2);
}

#[test]
fn crud_alerts() {
    let store = ResourceStore::new();
    let id1 = store.create(Resource::new("alert", "Alert 1"));
    let id2 = store.create(Resource::new("alert", "Alert 2"));
    let id3 = store.create(Resource::new("alert", "Alert 3"));

    assert_eq!(store.list("alert").len(), 3);
    assert!(store.get(&id1).is_some());
    assert!(store.get(&id2).is_some());
    assert!(store.get(&id3).is_some());

    assert!(store.delete(&id2, true));
    assert_eq!(store.list("alert").len(), 2);
    assert!(store.get(&id2).is_none());
}

#[test]
fn crud_mixed_types() {
    let store = ResourceStore::new();
    let task_id = store.create(Resource::new("task", "Task A"));
    let target_id = store.create(Resource::new("target", "Target A"));
    let config_id = store.create(Resource::new("config", "Config A"));

    let tasks = store.list("task");
    let targets = store.list("target");
    let configs = store.list("config");

    assert_eq!(tasks.len(), 1);
    assert_eq!(targets.len(), 1);
    assert_eq!(configs.len(), 1);
    assert_eq!(tasks[0].id, task_id);
    assert_eq!(targets[0].id, target_id);
    assert_eq!(configs[0].id, config_id);
}

#[test]
fn store_isolation() {
    let store = ResourceStore::new();
    let task_id = store.create(Resource::new("task", "Disposable Task"));
    store.create(Resource::new("target", "Persistent Target"));

    assert_eq!(store.count("target"), 1);
    assert!(store.delete(&task_id, true));
    assert_eq!(store.count("target"), 1);
}

#[test]
fn trash_mixed() {
    let store = ResourceStore::new();
    let task_id = store.create(Resource::new("task", "Trash Task"));
    let target_id = store.create(Resource::new("target", "Trash Target"));

    assert!(store.delete(&task_id, false));
    assert!(store.delete(&target_id, false));
    assert_eq!(store.list_trashed("task").len(), 1);
    assert_eq!(store.list_trashed("target").len(), 1);

    store.empty_trashcan();

    assert!(store.list_trashed("task").is_empty());
    assert!(store.list_trashed("target").is_empty());
    assert!(store.get(&task_id).is_none());
    assert!(store.get(&target_id).is_none());
}

#[test]
fn modify_nonexistent() {
    let store = ResourceStore::new();
    let missing = Uuid::new_v4();

    assert!(!store.modify(&missing, |resource| {
        resource.name = "Should Not Exist".to_string();
    }));
}

#[test]
fn concurrent_access() {
    let store = ResourceStore::new();

    for i in 0..100 {
        store.create(Resource::new("task", &format!("Task {i}")));
    }

    assert_eq!(store.count("task"), 100);
}

#[test]
fn resource_attrs() {
    let mut resource = Resource::new("config", "Attr Config");
    resource.set_attr("scanner", "scanner-1");
    resource.set_attr("family_count", "12");

    assert_eq!(resource.attr("scanner"), Some("scanner-1"));
    assert_eq!(resource.attr("family_count"), Some("12"));
    assert_eq!(resource.attr("missing"), None);
}
