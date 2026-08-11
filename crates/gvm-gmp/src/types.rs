// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Shared GMP types.

use std::fmt;
use std::num::NonZeroU16;
use std::str::FromStr;

/// A collection-valued update in a GMP modify request.
///
/// GMP distinguishes an omitted field (leave the current value unchanged),
/// a non-empty replacement, and an explicit request to clear the collection.
/// Command builders map [`Self::Clear`] to each command's gvmd-specific clear
/// representation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CollectionUpdate<T> {
    /// Omit the field and leave the stored collection unchanged.
    #[default]
    Omitted,
    /// Replace the stored collection with these values.
    Replace(Vec<T>),
    /// Explicitly clear the stored collection.
    Clear,
}

impl<T> CollectionUpdate<T> {
    /// Build a replacement for a non-empty collection.
    ///
    /// An empty iterator maps to [`Self::Clear`] so callers cannot
    /// accidentally lose the distinction between omission and clearing.
    #[must_use]
    pub fn replace(values: impl IntoIterator<Item = T>) -> Self {
        let values = values.into_iter().collect::<Vec<_>>();
        if values.is_empty() {
            Self::Clear
        } else {
            Self::Replace(values)
        }
    }
}

impl<T> From<Vec<T>> for CollectionUpdate<T> {
    fn from(values: Vec<T>) -> Self {
        Self::replace(values)
    }
}

/// A scalar-valued update in a GMP modify request.
///
/// GMP distinguishes an omitted relationship (leave it unchanged), setting it
/// to an entity, and explicitly clearing it. Command builders translate
/// [`Self::Clear`] to the command-specific wire representation so callers do
/// not need to construct protocol sentinel identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ScalarUpdate<T> {
    /// Omit the field and leave the stored value unchanged.
    #[default]
    Omitted,
    /// Set or replace the stored value.
    Set(T),
    /// Explicitly clear the stored value.
    Clear,
}

impl<T> ScalarUpdate<T> {
    /// Build an update that sets or replaces a scalar value.
    #[must_use]
    pub fn set(value: T) -> Self {
        Self::Set(value)
    }
}

impl<T> From<T> for ScalarUpdate<T> {
    fn from(value: T) -> Self {
        Self::Set(value)
    }
}

/// A validated GMP entity identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EntityId(String);

impl EntityId {
    /// Create a new entity identifier.
    ///
    /// # Errors
    /// Returns an error if the identifier is empty or contains invalid characters.
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

/// A validated TCP or UDP service port in the range `1..=65535`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct ServicePort(NonZeroU16);

impl ServicePort {
    /// Create a service port.
    ///
    /// # Errors
    /// Returns an error when `port` is zero.
    pub fn new(port: u16) -> Result<Self, ServicePortError> {
        NonZeroU16::new(port)
            .map(Self)
            .ok_or(ServicePortError::Zero)
    }

    /// Return the numeric port value.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl fmt::Display for ServicePort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(f)
    }
}

impl TryFrom<u16> for ServicePort {
    type Error = ServicePortError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ServicePort> for u16 {
    fn from(value: ServicePort) -> Self {
        value.get()
    }
}

/// Errors raised while validating a [`ServicePort`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ServicePortError {
    /// Port zero is reserved as a gvmd protocol sentinel and is not a service port.
    #[error("service port must be in the range 1..=65535")]
    Zero,
}

/// GMP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    fn service_port_rejects_zero() {
        assert_eq!(ServicePort::new(22).expect("valid port").get(), 22);
        assert_eq!(
            ServicePort::new(u16::MAX).expect("valid port").get(),
            65_535
        );
        assert_eq!(ServicePort::new(0), Err(ServicePortError::Zero));
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

    #[test]
    fn collection_update_preserves_omitted_replace_and_clear_states() {
        assert_eq!(
            CollectionUpdate::<String>::default(),
            CollectionUpdate::Omitted
        );
        assert_eq!(
            CollectionUpdate::replace(["one".to_string(), "two".to_string()]),
            CollectionUpdate::Replace(vec!["one".to_string(), "two".to_string()])
        );
        assert_eq!(
            CollectionUpdate::<String>::replace(Vec::new()),
            CollectionUpdate::Clear
        );
    }

    #[test]
    fn scalar_update_preserves_omitted_set_and_clear_states() {
        assert_eq!(ScalarUpdate::<String>::default(), ScalarUpdate::Omitted);
        assert_eq!(
            ScalarUpdate::set("entity-1".to_string()),
            ScalarUpdate::Set("entity-1".to_string())
        );
        assert_eq!(
            ScalarUpdate::from("entity-2".to_string()),
            ScalarUpdate::Set("entity-2".to_string())
        );
        assert_eq!(ScalarUpdate::<String>::Clear, ScalarUpdate::Clear);
    }
}
