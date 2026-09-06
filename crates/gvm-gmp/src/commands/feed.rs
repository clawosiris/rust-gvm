// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Feed command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::enums::FeedType;
use crate::responses::GetFeedsResponse;
use crate::GmpRequest;

/// Semantic request for listing every configured feed.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetFeedsRequest;

impl GetFeedsRequest {
    /// Create an all-feeds request.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Request for GetFeedsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_feeds().to_bytes()
    }
}

impl GmpRequest for GetFeedsRequest {
    type Response = GetFeedsResponse;
}

/// Semantic request for discovering one feed type.
#[derive(Debug, Clone, Copy)]
pub struct GetFeedRequest(FeedType);

impl GetFeedRequest {
    /// Create a type-filtered feed request.
    #[must_use]
    pub const fn new(feed_type: FeedType) -> Self {
        Self(feed_type)
    }
}

impl Request for GetFeedRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_feed(self.0).to_bytes()
    }
}

impl GmpRequest for GetFeedRequest {
    type Response = GetFeedsResponse;
}

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
