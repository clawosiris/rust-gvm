// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Feed command builders.

use gvm_protocol::XmlCommand;

use crate::enums::FeedType;

/// Build a `get_feeds` request.
#[must_use]
pub fn get_feeds() -> XmlCommand {
    XmlCommand::new("get_feeds")
}

/// Build a `get_feed` request.
#[must_use]
pub fn get_feed(feed_type: FeedType) -> XmlCommand {
    XmlCommand::new("get_feeds").attribute("type", feed_type.as_gmp_str())
}

#[cfg(test)]
mod tests {
    use crate::commands::feed::{get_feed, get_feeds};
    use crate::common::xml;
    use crate::FeedType;

    #[test]
    fn get_feeds_builds_xml() {
        assert_eq!(xml(get_feeds()), "<get_feeds/>");
    }

    #[test]
    fn get_feed_builds_xml() {
        assert_eq!(xml(get_feed(FeedType::Nvt)), "<get_feeds type=\"NVT\"/>");
        assert_eq!(
            xml(get_feed(FeedType::Gvmd)),
            "<get_feeds type=\"GVMD_DATA\"/>"
        );
    }
}
