// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Shared GMP types.

use std::fmt;
use std::str::FromStr;

/// A validated GMP entity identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntityId(String);

impl EntityId {
    /// Create a new entity identifier.
    pub fn new(id: impl Into<String>) -> Result<Self, EntityIdError> {
        let id = id.into();
        if id.is_empty() {
            return Err(EntityIdError::Empty);
        }
        if !id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        {
            return Err(EntityIdError::Invalid(id));
        }
        Ok(Self(id))
    }

    /// Borrow the identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EntityId {
    type Err = EntityIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// Errors raised while validating an [`EntityId`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EntityIdError {
    /// The identifier was empty.
    #[error("entity id cannot be empty")]
    Empty,
    /// The identifier contains unsupported characters.
    #[error("entity id contains unsupported characters: {0}")]
    Invalid(String),
}

/// GMP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GmpVersion(
    /// The major GMP version component.
    pub u16,
    /// The minor GMP version component.
    pub u16,
);

impl fmt::Display for GmpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.0, self.1)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn entity_id_accepts_valid_values() {
        let id = EntityId::new("550e8400-e29b-41d4-a716-446655440000").expect("valid id");
        assert_eq!(id.as_str(), "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn entity_id_rejects_empty_values() {
        assert_eq!(
            EntityId::new("").expect_err("empty id"),
            EntityIdError::Empty
        );
    }

    #[test]
    fn entity_id_round_trips_display_and_hash() {
        let id = EntityId::new("task-1").expect("valid id");
        assert_eq!(id.to_string(), "task-1");
        let mut ids = HashSet::new();
        ids.insert(id.clone());
        assert!(ids.contains(&id));
    }

    #[test]
    fn gmp_version_formats() {
        assert_eq!(GmpVersion(22, 5).to_string(), "22.5");
    }
}
