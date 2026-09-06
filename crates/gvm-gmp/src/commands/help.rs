// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Help command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::enums::HelpFormat as SchemaFormat;
use crate::responses::HelpResponse;
use crate::GmpRequest;

/// Supported help output formats.
///
/// This compatibility enum selects the XML command-listing variants. Use
/// [`HelpMode`] for new code that also needs text or another schema format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HelpFormat {
    /// Abbreviated command listing.
    Brief,
    /// Full command listing.
    Full,
}

impl HelpFormat {
    /// Return the legacy symbolic value.
    ///
    /// These values describe the compatibility variants; [`help`] maps them
    /// to gvmd's valid `format` and `type` attribute combination.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::Brief => "brief",
            Self::Full => "full",
        }
    }
}

/// Valid help response modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HelpMode {
    /// Plain-text command summary.
    #[default]
    Text,
    /// Abbreviated XML command listing.
    BriefXml,
    /// Complete schema in the selected format.
    Schema(SchemaFormat),
}

/// Semantic compatibility request for [`help`].
#[derive(Debug, Clone, Copy, Default)]
pub struct HelpRequest(Option<HelpFormat>);

impl HelpRequest {
    /// Create a compatibility help request.
    #[must_use]
    pub const fn new(format: Option<HelpFormat>) -> Self {
        Self(format)
    }
}

impl Request for HelpRequest {
    fn to_bytes(&self) -> Vec<u8> {
        help(self.0).to_bytes()
    }
}

impl GmpRequest for HelpRequest {
    type Response = HelpResponse;
}

/// Semantic request for an explicit help response mode.
#[derive(Debug, Clone, Copy, Default)]
pub struct HelpWithModeRequest(HelpMode);

impl HelpWithModeRequest {
    /// Create an explicit-mode help request.
    #[must_use]
    pub const fn new(mode: HelpMode) -> Self {
        Self(mode)
    }
}

impl Request for HelpWithModeRequest {
    fn to_bytes(&self) -> Vec<u8> {
        help_with_mode(self.0).to_bytes()
    }
}

impl GmpRequest for HelpWithModeRequest {
    type Response = HelpResponse;
}

/// Build a `help` request.
///
/// `Brief` and `Full` are retained for source compatibility and now map to
/// gvmd's valid XML help attributes. Older releases incorrectly placed these
/// values in the `format` attribute.
#[must_use]
pub fn help(format: Option<HelpFormat>) -> XmlCommand {
    match format {
        Some(HelpFormat::Brief) => help_with_mode(HelpMode::BriefXml),
        Some(HelpFormat::Full) => help_with_mode(HelpMode::Schema(SchemaFormat::Xml)),
        None => help_with_mode(HelpMode::Text),
    }
}

/// Build a `help` request for an explicit response mode.
#[must_use]
pub fn help_with_mode(mode: HelpMode) -> XmlCommand {
    let mut cmd = XmlCommand::new("help");
    match mode {
        HelpMode::Text => {}
        HelpMode::BriefXml => {
            cmd.set_attribute("format", SchemaFormat::Xml.as_gmp_str());
            cmd.set_attribute("type", "brief");
        }
        HelpMode::Schema(format) => {
            cmd.set_attribute("format", format.as_gmp_str());
        }
    }
    cmd
}

#[cfg(test)]
mod tests {
    use crate::commands::help::{help, help_with_mode, HelpFormat, HelpMode};
    use crate::common::xml;
    use crate::enums::HelpFormat as SchemaFormat;

    #[test]
    fn compatibility_help_builds_valid_xml_modes() {
        assert_eq!(HelpFormat::Brief.as_gmp_str(), "brief");
        assert_eq!(HelpFormat::Full.as_gmp_str(), "full");
        assert_eq!(xml(help(None)), "<help/>");
        assert_eq!(
            xml(help(Some(HelpFormat::Brief))),
            "<help format=\"xml\" type=\"brief\"/>"
        );
        assert_eq!(xml(help(Some(HelpFormat::Full))), "<help format=\"xml\"/>");
    }

    #[test]
    fn explicit_help_modes_build_valid_wire_shapes() {
        assert_eq!(xml(help_with_mode(HelpMode::Text)), "<help/>");
        assert_eq!(
            xml(help_with_mode(HelpMode::BriefXml)),
            "<help format=\"xml\" type=\"brief\"/>"
        );
        assert_eq!(
            xml(help_with_mode(HelpMode::Schema(SchemaFormat::Html))),
            "<help format=\"html\"/>"
        );
    }
}
