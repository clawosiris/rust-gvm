// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! System-report command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::bool_str;
use crate::responses::GetSystemReportsResponse;
use crate::types::EntityId;
use crate::GmpRequest;

/// Options for `get_system_reports` requests.
#[derive(Debug, Clone, Default)]
pub struct GetSystemReportsOpts {
    /// Name of a single system report to retrieve.
    pub name: Option<String>,
    /// Number of seconds into the past to include.
    pub duration: Option<u64>,
    /// Start of the requested interval as an ISO timestamp.
    pub start_time: Option<String>,
    /// End of the requested interval as an ISO timestamp.
    pub end_time: Option<String>,
    /// Whether to list report metadata without the report payload.
    pub brief: Option<bool>,
    /// Scanner from which to retrieve the report.
    pub slave_id: Option<EntityId>,
}

/// Semantic request for system-report discovery.
#[derive(Debug, Clone, Default)]
pub struct GetSystemReportsRequest(GetSystemReportsOpts);

impl GetSystemReportsRequest {
    /// Create a system-report request.
    #[must_use]
    pub fn new(opts: GetSystemReportsOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetSystemReportsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_system_reports(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetSystemReportsRequest {
    type Response = GetSystemReportsResponse;
}

/// Build a `get_system_reports` request.
#[must_use]
pub fn get_system_reports(opts: GetSystemReportsOpts) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_system_reports");
    if let Some(name) = opts.name.as_deref() {
        cmd.set_attribute("name", name);
    }
    if let Some(duration) = opts.duration {
        cmd.set_attribute("duration", &duration.to_string());
    }
    if let Some(start_time) = opts.start_time.as_deref() {
        cmd.set_attribute("start_time", start_time);
    }
    if let Some(end_time) = opts.end_time.as_deref() {
        cmd.set_attribute("end_time", end_time);
    }
    if let Some(brief) = opts.brief {
        cmd.set_attribute("brief", bool_str(brief));
    }
    if let Some(slave_id) = opts.slave_id.as_ref() {
        cmd.set_attribute("slave_id", slave_id.as_str());
    }
    cmd
}

#[cfg(test)]
mod tests {
    use crate::commands::system_reports::{get_system_reports, GetSystemReportsOpts};
    use crate::common::xml;
    use crate::types::EntityId;

    #[test]
    fn get_system_reports_builds_xml() {
        assert_eq!(
            xml(get_system_reports(GetSystemReportsOpts {
                name: Some("load".into()),
                duration: Some(3600),
                start_time: Some("2026-07-23T12:00:00Z".into()),
                end_time: Some("2026-07-23T13:00:00Z".into()),
                brief: Some(false),
                slave_id: Some(EntityId::new("scanner-1").expect("valid id")),
            })),
            "<get_system_reports brief=\"0\" duration=\"3600\" end_time=\"2026-07-23T13:00:00Z\" name=\"load\" slave_id=\"scanner-1\" start_time=\"2026-07-23T12:00:00Z\"/>"
        );
    }
}
