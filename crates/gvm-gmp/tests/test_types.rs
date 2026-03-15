// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use std::collections::HashSet;
use std::str::FromStr;

use gvm_gmp::{EntityId, EntityIdError};

#[test]
fn test_entity_id_accepts_valid_uuid() {
    let id = EntityId::new("550e8400-e29b-41d4-a716-446655440000").unwrap();
    assert_eq!(id.as_str(), "550e8400-e29b-41d4-a716-446655440000");
}

#[test]
fn test_entity_id_rejects_empty_string() {
    assert_eq!(EntityId::new("").unwrap_err(), EntityIdError::Empty);
}

#[test]
fn test_entity_id_rejects_whitespace_only() {
    assert!(matches!(
        EntityId::new("   ").unwrap_err(),
        EntityIdError::Invalid(_)
    ));
}

#[test]
fn test_entity_id_rejects_special_characters() {
    assert!(matches!(
        EntityId::new("bad:id").unwrap_err(),
        EntityIdError::Invalid(_)
    ));
}

#[test]
fn test_entity_id_display_hash_and_eq_work() {
    let id = EntityId::new("task-1").unwrap();
    let mut set = HashSet::new();
    set.insert(id.clone());
    assert_eq!(id.to_string(), "task-1");
    assert!(set.contains(&id));
    assert_eq!(id, EntityId::new("task-1").unwrap());
}

#[test]
fn test_entity_id_from_str_works() {
    assert_eq!(EntityId::from_str("abc_123").unwrap().as_str(), "abc_123");
}
