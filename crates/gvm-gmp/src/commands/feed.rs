// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Feed command builders.

use gvm_protocol::XmlCommand;

/// Build a `get_feeds` request.
#[must_use]
pub fn get_feeds() -> XmlCommand {
    XmlCommand::new("get_feeds")
}

#[cfg(test)]
mod tests {
    use crate::commands::feed::get_feeds;
    use crate::common::xml;

    #[test]
    fn get_feeds_builds_xml() {
        assert_eq!(xml(get_feeds()), "<get_feeds/>");
    }
}
