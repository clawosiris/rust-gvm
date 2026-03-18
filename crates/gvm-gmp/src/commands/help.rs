// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Help command builders.

use gvm_protocol::XmlCommand;

/// Supported help output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HelpFormat {
    /// Abbreviated command listing.
    Brief,
    /// Full command listing.
    Full,
}

impl HelpFormat {
    /// Returns the GMP wire-format string for this value.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::Brief => "brief",
            Self::Full => "full",
        }
    }
}

/// Build a `help` request.
#[must_use]
pub fn help(format: Option<HelpFormat>) -> XmlCommand {
    let mut cmd = XmlCommand::new("help");
    if let Some(format) = format {
        cmd.set_attribute("format", format.as_gmp_str());
    }
    cmd
}

#[cfg(test)]
mod tests {
    use crate::commands::help::{help, HelpFormat};
    use crate::common::xml;

    #[test]
    fn help_format_variants_map_to_wire_values() {
        assert_eq!(HelpFormat::Brief.as_gmp_str(), "brief");
        assert_eq!(HelpFormat::Full.as_gmp_str(), "full");
    }

    #[test]
    fn help_builds_xml() {
        assert_eq!(xml(help(None)), "<help/>");
        assert_eq!(
            xml(help(Some(HelpFormat::Brief))),
            "<help format=\"brief\"/>"
        );
        assert_eq!(xml(help(Some(HelpFormat::Full))), "<help format=\"full\"/>");
    }
}
