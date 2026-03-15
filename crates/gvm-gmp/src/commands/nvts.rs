// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! NVT command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::types::EntityId;

/// Options for `get_nvts` requests.
#[derive(Debug, Clone, Default)]
pub struct GetNvtsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Build a `get_nvts` request.
#[must_use]
pub fn get_nvts(opts: GetNvtsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_nvts");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_nvts` request for a single NVT.
#[must_use]
pub fn get_nvt(nvt_oid: &str) -> impl Request {
    XmlCommand::new("get_nvts")
        .attribute("nvt_oid", nvt_oid)
        .attribute("details", "1")
}

/// Build a `get_nvt_families` request.
#[must_use]
pub fn get_nvt_families() -> impl Request {
    XmlCommand::new("get_nvt_families")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn nvt_commands_build_xml() {
        let rendered = xml(get_nvts(GetNvtsOpts {
            filter_id: Some(id("f1")),
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("filt_id=\"f1\""));
        assert!(rendered.contains("details=\"1\""));
        assert_eq!(
            xml(get_nvt("1.3.6.1")),
            "<get_nvts details=\"1\" nvt_oid=\"1.3.6.1\"/>"
        );
        assert_eq!(xml(get_nvt_families()), "<get_nvt_families/>");
    }
}
