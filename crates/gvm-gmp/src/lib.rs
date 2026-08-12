// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(clippy::needless_pass_by_value)]

//! Typed GMP command builders.

/// Authoritative GMP command capability registry.
pub mod capabilities;
/// GMP command-builder modules.
pub mod commands;
mod common;
/// GMP enums and wire-format helpers.
pub mod enums;
/// Shared gvmd filter composition helpers.
pub mod filtering;
/// Typed GMP response models.
pub mod responses;
/// Typed schedule recurrence and iCalendar helpers.
pub mod schedule;
/// Validated target-host specifications.
pub mod target;
/// Shared GMP identifier and version types.
pub mod types;

/// Re-exported GMP enums.
pub use enums::*;
/// Re-exported gvmd filter helpers.
pub use filtering::{FilterFragment, FilterFragmentError, PaginatedFilter, Pagination};
/// Re-exported typed schedule values.
pub use schedule::{
    ScheduleDefinition, ScheduleIcalendarError, ScheduleInput, ScheduleObservation,
    ScheduleRecurrence, ScheduleRecurrenceObservation, ScheduleStartObservation, ScheduleTimestamp,
    ScheduleTimestampError, ScheduleTimezone, ScheduleTimezoneError,
};
/// Re-exported validated target-host values.
pub use target::{
    TargetHost, TargetHostError, TargetHostErrorKind, TargetHostKind, TargetHosts,
    TargetHostsError, TargetPortRange, TargetPortRangeError, TargetPortSelection,
};
/// Re-exported shared GMP types.
pub use types::{
    CollectionUpdate, EntityId, EntityIdError, GmpVersion, ScalarUpdate, ServicePort,
    ServicePortError,
};
