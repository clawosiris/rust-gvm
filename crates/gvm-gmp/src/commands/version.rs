// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Version command builders.

use gvm_protocol::{Request, XmlCommand};

/// Build a `get_version` command.
#[must_use]
pub fn get_version() -> impl Request {
    XmlCommand::new("get_version")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    #[test]
    fn get_version_builds_xml() {
        assert_eq!(xml(get_version()), "<get_version/>");
    }
}
