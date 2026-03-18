// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! System-report command builders.

use gvm_protocol::XmlCommand;

use crate::common::add_filter_attrs;
use crate::types::EntityId;

/// Options for `get_system_reports` requests.
#[derive(Debug, Clone, Default)]
pub struct GetSystemReportsOpts {
    /// Optional inline filter expression.
    pub filter: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
}

/// Build a `get_system_reports` request.
#[must_use]
pub fn get_system_reports(opts: GetSystemReportsOpts) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_system_reports");
    add_filter_attrs(&mut cmd, opts.filter.as_deref(), opts.filter_id.as_ref());
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
                filter: Some("name=load".into()),
                filter_id: Some(EntityId::new("f1").expect("valid id")),
            })),
            "<get_system_reports filt_id=\"f1\" filter=\"name=load\"/>"
        );
    }
}
