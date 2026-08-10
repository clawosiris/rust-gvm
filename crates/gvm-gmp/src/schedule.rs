// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Typed schedule values and the supported iCalendar subset.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, LocalResult, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use chrono_tz::Tz;
use uuid::Uuid;

use crate::commands::schedules::ScheduleOpts;

/// A normalized UTC timestamp used by typed schedule APIs.
///
/// Input accepts RFC 3339 timestamps. Values are normalized to UTC with second
/// precision, for example `2026-08-10T12:30:00Z`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ScheduleTimestamp(String);

impl ScheduleTimestamp {
    /// Parse and normalize an RFC 3339 timestamp.
    ///
    /// # Errors
    /// Returns an error when `value` is not a valid RFC 3339 timestamp.
    pub fn parse(value: &str) -> Result<Self, ScheduleTimestampError> {
        let parsed = DateTime::parse_from_rfc3339(value)
            .map_err(|_| ScheduleTimestampError(value.to_string()))?;
        Ok(Self(
            parsed
                .with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Secs, true),
        ))
    }

    /// Return the normalized RFC 3339 representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn to_icalendar_value(&self) -> String {
        DateTime::parse_from_rfc3339(&self.0)
            .expect("ScheduleTimestamp invariant")
            .with_timezone(&Utc)
            .format("%Y%m%dT%H%M%SZ")
            .to_string()
    }

    fn from_utc_datetime(value: NaiveDateTime) -> Self {
        Self(value.and_utc().to_rfc3339_opts(SecondsFormat::Secs, true))
    }

    fn from_zoned_datetime<T: TimeZone>(value: DateTime<T>) -> Self {
        Self(
            value
                .with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Secs, true),
        )
    }
}

impl fmt::Display for ScheduleTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ScheduleTimestamp {
    type Err = ScheduleTimestampError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ScheduleTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// Error returned for an invalid typed schedule timestamp.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid RFC 3339 schedule timestamp: {0}")]
pub struct ScheduleTimestampError(String);

/// A non-empty gvmd schedule timezone name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ScheduleTimezone(String);

impl ScheduleTimezone {
    /// Validate a timezone name.
    ///
    /// The name is sent to gvmd for authoritative timezone validation.
    ///
    /// # Errors
    /// Returns an error for an empty or whitespace-only value.
    pub fn new(value: impl Into<String>) -> Result<Self, ScheduleTimezoneError> {
        let value = value.into();
        if value.trim().is_empty() {
            Err(ScheduleTimezoneError)
        } else {
            Ok(Self(value))
        }
    }

    /// Return the timezone name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ScheduleTimezone {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ScheduleTimezone {
    type Err = ScheduleTimezoneError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ScheduleTimezone {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Error returned for an empty schedule timezone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("schedule timezone must not be empty")]
pub struct ScheduleTimezoneError;

/// Recurrence forms supported by the typed schedule API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum ScheduleRecurrence {
    /// Run once at the first-run time.
    Once,
    /// Repeat every hour.
    Hourly,
    /// Repeat every day.
    Daily,
    /// Repeat every week.
    Weekly,
    /// Repeat every year.
    Yearly,
}

impl ScheduleRecurrence {
    fn frequency(self) -> Option<&'static str> {
        match self {
            Self::Once => None,
            Self::Hourly => Some("HOURLY"),
            Self::Daily => Some("DAILY"),
            Self::Weekly => Some("WEEKLY"),
            Self::Yearly => Some("YEARLY"),
        }
    }
}

/// First-run and recurrence semantics for a supported schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScheduleDefinition {
    /// First scheduled run, normalized to UTC and second precision.
    pub first_run: ScheduleTimestamp,
    /// Recurrence anchored at `first_run`.
    pub recurrence: ScheduleRecurrence,
}

/// Typed input for schedule create and modify commands.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScheduleInput {
    /// First-run and recurrence definition.
    pub definition: ScheduleDefinition,
    /// Timezone passed to gvmd.
    pub timezone: ScheduleTimezone,
    /// Optional resource comment.
    pub comment: Option<String>,
    /// Optional renamed resource name for modify operations.
    pub name: Option<String>,
}

impl ScheduleInput {
    /// Create typed schedule input without optional metadata.
    #[must_use]
    pub fn new(definition: ScheduleDefinition, timezone: ScheduleTimezone) -> Self {
        Self {
            definition,
            timezone,
            comment: None,
            name: None,
        }
    }

    /// Serialize this input into the raw compatibility options.
    #[must_use]
    pub fn into_raw(self) -> ScheduleOpts {
        ScheduleOpts {
            comment: self.comment,
            icalendar: Some(to_icalendar(&self.definition)),
            timezone: Some(self.timezone.0),
            name: self.name,
        }
    }
}

impl From<ScheduleInput> for ScheduleOpts {
    fn from(value: ScheduleInput) -> Self {
        value.into_raw()
    }
}

/// Recurrence observed in a schedule response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum ScheduleRecurrenceObservation {
    /// A recurrence supported by the typed input API.
    Supported(ScheduleRecurrence),
    /// A valid recurrence rule outside the supported subset.
    Unsupported {
        /// Original recurrence-affecting properties.
        value: String,
    },
}

/// First-run timestamp observed in a schedule iCalendar payload.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum ScheduleStartObservation {
    /// Timestamp resolved and normalized to UTC with second precision.
    Supported(ScheduleTimestamp),
    /// Syntactically valid timestamp whose timezone semantics are not supported.
    Unsupported {
        /// Original `DTSTART` value.
        value: String,
        /// `TZID` parameter or fallback schedule timezone, when available.
        timezone: Option<String>,
    },
}

impl ScheduleStartObservation {
    /// Return the resolved timestamp when the start is supported.
    #[must_use]
    pub fn timestamp(&self) -> Option<&ScheduleTimestamp> {
        match self {
            Self::Supported(timestamp) => Some(timestamp),
            Self::Unsupported { .. } => None,
        }
    }
}

/// Typed schedule semantics parsed from an observed iCalendar payload.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScheduleObservation {
    /// First run parsed from the first `VEVENT`'s `DTSTART`.
    pub first_run: ScheduleStartObservation,
    /// Parsed recurrence or an explicit unsupported representation.
    pub recurrence: ScheduleRecurrenceObservation,
}

/// Error returned when an iCalendar payload is malformed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScheduleIcalendarError {
    /// The payload is structurally or syntactically invalid.
    #[error("malformed schedule iCalendar: {0}")]
    Malformed(String),
}

/// Generate the canonical iCalendar payload for a typed schedule definition.
#[must_use]
pub fn to_icalendar(definition: &ScheduleDefinition) -> String {
    let start = definition.first_run.to_icalendar_value();
    let uid = Uuid::new_v4();
    let mut lines = vec![
        "BEGIN:VCALENDAR".to_string(),
        "VERSION:2.0".to_string(),
        "PRODID:-//Greenbone//rust-gvm//EN".to_string(),
        "BEGIN:VEVENT".to_string(),
        format!("UID:{uid}"),
        format!("DTSTAMP:{start}"),
        format!("DTSTART:{start}"),
    ];
    if let Some(frequency) = definition.recurrence.frequency() {
        lines.push(format!("RRULE:FREQ={frequency}"));
    }
    lines.extend(["END:VEVENT".to_string(), "END:VCALENDAR".to_string()]);
    format!("{}\r\n", lines.join("\r\n"))
}

/// Parse the supported schedule semantics from an iCalendar payload.
///
/// # Errors
/// Returns [`ScheduleIcalendarError::Malformed`] for invalid calendar syntax.
/// Unsupported but recognizable recurrence data is returned in the observation.
pub fn parse_icalendar(value: &str) -> Result<ScheduleObservation, ScheduleIcalendarError> {
    parse_icalendar_with_timezone(value, None)
}

/// Parse schedule semantics using the schedule's timezone when `DTSTART` is floating.
///
/// # Errors
/// Returns [`ScheduleIcalendarError::Malformed`] for invalid calendar syntax.
pub fn parse_icalendar_with_timezone(
    value: &str,
    fallback_timezone: Option<&str>,
) -> Result<ScheduleObservation, ScheduleIcalendarError> {
    let lines = unfold_lines(value)?;
    let properties = first_event_properties(&lines)?;
    let starts = properties
        .iter()
        .filter(|property| property.name.eq_ignore_ascii_case("DTSTART"))
        .collect::<Vec<_>>();
    if starts.len() != 1 {
        return Err(ScheduleIcalendarError::Malformed(
            "expected exactly one DTSTART".to_string(),
        ));
    }
    let first_run = parse_start(starts[0], fallback_timezone)?;
    let recurrence = parse_event_recurrence(&properties)?;
    Ok(ScheduleObservation {
        first_run,
        recurrence,
    })
}

fn unfold_lines(value: &str) -> Result<Vec<String>, ScheduleIcalendarError> {
    let mut lines: Vec<String> = Vec::new();
    for line in value.replace("\r\n", "\n").split('\n') {
        if line.starts_with([' ', '\t']) {
            let previous = lines.last_mut().ok_or_else(|| {
                ScheduleIcalendarError::Malformed("orphan folded line".to_string())
            })?;
            previous.push_str(&line[1..]);
        } else if !line.is_empty() {
            lines.push(line.to_string());
        }
    }
    Ok(lines)
}

#[derive(Debug)]
struct IcalendarProperty {
    name: String,
    params: Vec<(String, String)>,
    value: String,
    raw: String,
}

fn first_event_properties(
    lines: &[String],
) -> Result<Vec<IcalendarProperty>, ScheduleIcalendarError> {
    let mut components: Vec<String> = Vec::new();
    let mut properties = Vec::new();
    let mut found_event = false;
    let mut completed_event = false;

    for line in lines {
        if let Some(component) = line.strip_prefix("BEGIN:") {
            if component.is_empty() {
                return Err(ScheduleIcalendarError::Malformed(
                    "empty component name".to_string(),
                ));
            }
            if component.eq_ignore_ascii_case("VEVENT") && !found_event {
                found_event = true;
            }
            components.push(component.to_ascii_uppercase());
            continue;
        }
        if let Some(component) = line.strip_prefix("END:") {
            let Some(open) = components.pop() else {
                return Err(ScheduleIcalendarError::Malformed(
                    "unexpected component end".to_string(),
                ));
            };
            if !open.eq_ignore_ascii_case(component) {
                return Err(ScheduleIcalendarError::Malformed(format!(
                    "component end {component} does not match {open}"
                )));
            }
            if component.eq_ignore_ascii_case("VEVENT") && found_event && !completed_event {
                completed_event = true;
            }
            continue;
        }

        if found_event
            && !completed_event
            && components
                .last()
                .is_some_and(|component| component == "VEVENT")
        {
            properties.push(parse_property(line)?);
        }
    }

    if !components.is_empty() {
        return Err(ScheduleIcalendarError::Malformed(
            "unclosed component".to_string(),
        ));
    }
    if !completed_event {
        return Err(ScheduleIcalendarError::Malformed(
            "expected a complete VEVENT".to_string(),
        ));
    }
    Ok(properties)
}

fn parse_property(line: &str) -> Result<IcalendarProperty, ScheduleIcalendarError> {
    let (head, value) = line.split_once(':').ok_or_else(|| {
        ScheduleIcalendarError::Malformed(format!("property is missing ':': {line}"))
    })?;
    let mut parts = head.split(';');
    let name = parts.next().unwrap_or_default();
    if name.is_empty() {
        return Err(ScheduleIcalendarError::Malformed(
            "property name must not be empty".to_string(),
        ));
    }
    let params = parts
        .map(|part| {
            let (name, value) = part.split_once('=').ok_or_else(|| {
                ScheduleIcalendarError::Malformed(format!("invalid property parameter: {part}"))
            })?;
            if name.is_empty() || value.is_empty() {
                return Err(ScheduleIcalendarError::Malformed(format!(
                    "invalid property parameter: {part}"
                )));
            }
            Ok((name.to_string(), value.trim_matches('"').to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(IcalendarProperty {
        name: name.to_string(),
        params,
        value: value.to_string(),
        raw: line.to_string(),
    })
}

fn parse_start(
    property: &IcalendarProperty,
    fallback_timezone: Option<&str>,
) -> Result<ScheduleStartObservation, ScheduleIcalendarError> {
    let parameter = |name: &str| {
        property
            .params
            .iter()
            .find(|(parameter, _)| parameter.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };
    let timezone = parameter("TZID").or(fallback_timezone);
    if parameter("VALUE").is_some_and(|value| value.eq_ignore_ascii_case("DATE")) {
        return Ok(ScheduleStartObservation::Unsupported {
            value: property.value.clone(),
            timezone: timezone.map(str::to_string),
        });
    }
    if let Some(value) = property.value.strip_suffix('Z') {
        let parsed = NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%S").map_err(|_| {
            ScheduleIcalendarError::Malformed(format!("invalid UTC DTSTART: {}", property.value))
        })?;
        return Ok(ScheduleStartObservation::Supported(
            ScheduleTimestamp::from_utc_datetime(parsed),
        ));
    }
    let parsed = NaiveDateTime::parse_from_str(&property.value, "%Y%m%dT%H%M%S").map_err(|_| {
        ScheduleIcalendarError::Malformed(format!("invalid DTSTART: {}", property.value))
    })?;
    let Some(timezone_name) = timezone else {
        return Ok(ScheduleStartObservation::Unsupported {
            value: property.value.clone(),
            timezone: None,
        });
    };
    let Ok(timezone) = timezone_name.parse::<Tz>() else {
        return Ok(ScheduleStartObservation::Unsupported {
            value: property.value.clone(),
            timezone: Some(timezone_name.to_string()),
        });
    };
    match timezone.from_local_datetime(&parsed) {
        LocalResult::Single(value) => Ok(ScheduleStartObservation::Supported(
            ScheduleTimestamp::from_zoned_datetime(value),
        )),
        LocalResult::Ambiguous(_, _) | LocalResult::None => {
            Ok(ScheduleStartObservation::Unsupported {
                value: property.value.clone(),
                timezone: Some(timezone_name.to_string()),
            })
        }
    }
}

fn parse_event_recurrence(
    properties: &[IcalendarProperty],
) -> Result<ScheduleRecurrenceObservation, ScheduleIcalendarError> {
    let recurrence_properties = properties
        .iter()
        .filter(|property| {
            ["RRULE", "RDATE", "EXDATE", "EXRULE", "RECURRENCE-ID"]
                .iter()
                .any(|name| property.name.eq_ignore_ascii_case(name))
        })
        .collect::<Vec<_>>();
    if recurrence_properties.is_empty() {
        return Ok(ScheduleRecurrenceObservation::Supported(
            ScheduleRecurrence::Once,
        ));
    }
    let rules = recurrence_properties
        .iter()
        .filter(|property| property.name.eq_ignore_ascii_case("RRULE"))
        .collect::<Vec<_>>();
    let parsed_rule = match rules.as_slice() {
        [] => None,
        [rule] => Some(parse_recurrence(&rule.value)?),
        _ => None,
    };
    if recurrence_properties.len() == 1 {
        if let Some(parsed_rule) = parsed_rule {
            return Ok(parsed_rule);
        }
    }
    Ok(ScheduleRecurrenceObservation::Unsupported {
        value: recurrence_properties
            .iter()
            .map(|property| property.raw.as_str())
            .collect::<Vec<_>>()
            .join("\r\n"),
    })
}

fn parse_recurrence(rule: &str) -> Result<ScheduleRecurrenceObservation, ScheduleIcalendarError> {
    let mut frequency = None;
    let mut unsupported = false;
    for part in rule.split(';') {
        let (name, value) = part.split_once('=').ok_or_else(|| {
            ScheduleIcalendarError::Malformed(format!("invalid RRULE component: {part}"))
        })?;
        if name.eq_ignore_ascii_case("FREQ") {
            if frequency.replace(value).is_some() || value.is_empty() {
                return Err(ScheduleIcalendarError::Malformed(
                    "RRULE must contain one non-empty FREQ".to_string(),
                ));
            }
        } else if name.eq_ignore_ascii_case("INTERVAL") && value == "1" {
        } else {
            unsupported = true;
        }
    }
    let Some(frequency) = frequency else {
        return Err(ScheduleIcalendarError::Malformed(
            "RRULE is missing FREQ".to_string(),
        ));
    };
    let recurrence = match frequency.to_ascii_uppercase().as_str() {
        "HOURLY" => Some(ScheduleRecurrence::Hourly),
        "DAILY" => Some(ScheduleRecurrence::Daily),
        "WEEKLY" => Some(ScheduleRecurrence::Weekly),
        "YEARLY" => Some(ScheduleRecurrence::Yearly),
        _ => None,
    };
    match recurrence {
        Some(recurrence) if !unsupported => {
            Ok(ScheduleRecurrenceObservation::Supported(recurrence))
        }
        _ => Ok(ScheduleRecurrenceObservation::Unsupported {
            value: rule.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definition(recurrence: ScheduleRecurrence) -> ScheduleDefinition {
        ScheduleDefinition {
            first_run: ScheduleTimestamp::parse("2026-08-10T12:30:00+02:00")
                .expect("valid timestamp"),
            recurrence,
        }
    }

    #[test]
    fn round_trips_supported_recurrences() {
        for recurrence in [
            ScheduleRecurrence::Once,
            ScheduleRecurrence::Hourly,
            ScheduleRecurrence::Daily,
            ScheduleRecurrence::Weekly,
            ScheduleRecurrence::Yearly,
        ] {
            let parsed = parse_icalendar(&to_icalendar(&definition(recurrence)))
                .expect("generated calendar should parse");
            assert_eq!(
                parsed.first_run,
                ScheduleStartObservation::Supported(definition(recurrence).first_run)
            );
            assert_eq!(
                parsed.recurrence,
                ScheduleRecurrenceObservation::Supported(recurrence)
            );
        }
    }

    #[test]
    fn distinguishes_unsupported_recurrence_from_once() {
        let calendar = to_icalendar(&definition(ScheduleRecurrence::Daily))
            .replace("FREQ=DAILY", "FREQ=MONTHLY;BYMONTHDAY=1");
        let parsed =
            parse_icalendar(&calendar).expect("unsupported rules should remain observable");
        assert!(matches!(
            parsed.recurrence,
            ScheduleRecurrenceObservation::Unsupported { .. }
        ));
    }

    #[test]
    fn rejects_malformed_calendar() {
        let error = parse_icalendar("BEGIN:VCALENDAR\nEND:VCALENDAR")
            .expect_err("eventless calendar should fail");
        assert!(matches!(error, ScheduleIcalendarError::Malformed(_)));
    }

    #[test]
    fn unfolds_lines() {
        let calendar = to_icalendar(&definition(ScheduleRecurrence::Daily))
            .replace("RRULE:FREQ=DAILY", "RRULE:FREQ=DAI\r\n LY");
        let parsed = parse_icalendar(&calendar).expect("folded rule should parse");
        assert_eq!(
            parsed.recurrence,
            ScheduleRecurrenceObservation::Supported(ScheduleRecurrence::Daily)
        );
    }

    #[test]
    fn ignores_timezone_component_starts_and_resolves_event_timezone() {
        let calendar = "BEGIN:VCALENDAR\r\n\
            BEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\n\
            BEGIN:STANDARD\r\nDTSTART:19701025T030000\r\nEND:STANDARD\r\n\
            BEGIN:DAYLIGHT\r\nDTSTART:19700329T020000\r\nEND:DAYLIGHT\r\n\
            END:VTIMEZONE\r\nBEGIN:VEVENT\r\n\
            DTSTART;TZID=Europe/Berlin:20300101T080000\r\n\
            RRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

        let parsed = parse_icalendar_with_timezone(calendar, Some("UTC"))
            .expect("canonical gvmd calendar parses");

        assert_eq!(
            parsed.first_run.timestamp().map(ScheduleTimestamp::as_str),
            Some("2030-01-01T07:00:00Z")
        );
        assert_eq!(
            parsed.recurrence,
            ScheduleRecurrenceObservation::Supported(ScheduleRecurrence::Weekly)
        );
    }

    #[test]
    fn resolves_floating_start_with_schedule_timezone() {
        let calendar = "BEGIN:VEVENT\r\nDTSTART:20300101T080000\r\nEND:VEVENT\r\n";
        let parsed = parse_icalendar_with_timezone(calendar, Some("Europe/Berlin"))
            .expect("floating start parses");
        assert_eq!(
            parsed.first_run.timestamp().map(ScheduleTimestamp::as_str),
            Some("2030-01-01T07:00:00Z")
        );
    }

    #[test]
    fn unsupported_timezone_does_not_hide_supported_recurrence() {
        let calendar = "BEGIN:VEVENT\r\n\
            DTSTART;TZID=Custom/Zone:20300101T080000\r\n\
            RRULE:FREQ=DAILY\r\nEND:VEVENT\r\n";
        let parsed = parse_icalendar(calendar).expect("valid calendar remains observable");
        assert!(matches!(
            parsed.first_run,
            ScheduleStartObservation::Unsupported { .. }
        ));
        assert_eq!(
            parsed.recurrence,
            ScheduleRecurrenceObservation::Supported(ScheduleRecurrence::Daily)
        );
    }

    #[test]
    fn ambiguous_and_nonexistent_local_starts_are_unsupported() {
        for value in ["20261025T023000", "20260329T023000"] {
            let calendar = format!("BEGIN:VEVENT\r\nDTSTART:{value}\r\nEND:VEVENT\r\n");
            let parsed = parse_icalendar_with_timezone(&calendar, Some("Europe/Berlin"))
                .expect("valid local time syntax parses");
            assert!(matches!(
                parsed.first_run,
                ScheduleStartObservation::Unsupported { .. }
            ));
        }
    }

    #[test]
    fn recurrence_dates_are_not_misreported_as_once() {
        for property in ["RDATE:20300102T080000Z", "EXDATE:20300102T080000Z"] {
            let calendar =
                format!("BEGIN:VEVENT\r\nDTSTART:20300101T080000Z\r\n{property}\r\nEND:VEVENT\r\n");
            let parsed = parse_icalendar(&calendar).expect("valid recurrence date parses");
            assert!(matches!(
                parsed.recurrence,
                ScheduleRecurrenceObservation::Unsupported { .. }
            ));
        }
    }

    #[test]
    fn uses_the_first_event_like_gvmd() {
        let calendar = "BEGIN:VCALENDAR\r\n\
            BEGIN:VEVENT\r\nDTSTART:20300101T080000Z\r\nEND:VEVENT\r\n\
            BEGIN:VEVENT\r\nDTSTART:20400101T080000Z\r\nEND:VEVENT\r\n\
            END:VCALENDAR\r\n";
        let parsed = parse_icalendar(calendar).expect("first event parses");
        assert_eq!(
            parsed.first_run.timestamp().map(ScheduleTimestamp::as_str),
            Some("2030-01-01T08:00:00Z")
        );
    }
}
