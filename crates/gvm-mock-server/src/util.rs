// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Shared utilities for timestamps and XML escaping.

use std::time::SystemTime;

pub(crate) fn now_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    epoch_to_iso(secs)
}

pub(crate) fn epoch_to_iso(secs: u64) -> String {
    let mut days = (secs / 86_400) as i64;
    let day_secs = (secs % 86_400) as u32;
    let hours = day_secs / 3_600;
    let minutes = (day_secs % 3_600) / 60;
    let seconds = day_secs % 60;

    days += 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = (days - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

pub(crate) fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub(crate) fn xml_escape_attr(value: &str) -> String {
    xml_escape(value).replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_to_iso_epoch() {
        assert_eq!(epoch_to_iso(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_xml_escape_attr() {
        assert_eq!(xml_escape_attr("\"<&>'"), "&quot;&lt;&amp;&gt;&apos;");
    }
}
