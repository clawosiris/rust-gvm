//! GMP version parsing and negotiation helpers.

use gvm_gmp::types::GmpVersion;

use crate::GvmError;

/// Parse a GMP version string into a major/minor pair.
///
/// Accepts `major.minor` and ignores any later dot-separated components.
///
/// # Errors
/// Returns an error if the string does not start with two numeric components.
pub fn parse_version_text(input: &str) -> Result<GmpVersion, GvmError> {
    let value = input.trim();
    let mut parts = value.split('.');

    let major = parts
        .next()
        .ok_or_else(|| GvmError::XmlParse(format!("invalid version string: {value}")))?
        .parse::<u16>()
        .map_err(|_| GvmError::XmlParse(format!("invalid version string: {value}")))?;
    let minor = parts
        .next()
        .ok_or_else(|| GvmError::XmlParse(format!("invalid version string: {value}")))?
        .parse::<u16>()
        .map_err(|_| GvmError::XmlParse(format!("invalid version string: {value}")))?;

    Ok(GmpVersion(major, minor))
}

/// Map a negotiated GMP version into the supported client version set.
///
/// # Errors
/// Returns an error if the major version is unsupported or the minor version is
/// older than the supported range.
pub fn map_supported_version(version: GmpVersion) -> Result<GmpVersion, GvmError> {
    match version {
        GmpVersion(22, 4..=7) => Ok(version),
        GmpVersion(22, minor) if minor > 7 => Ok(version),
        GmpVersion(major, minor) => Err(GvmError::UnsupportedVersion(major, minor)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_major_minor() {
        assert_eq!(parse_version_text("22.5").expect("valid"), GmpVersion(22, 5));
    }

    #[test]
    fn parses_major_minor_with_patch_suffix() {
        assert_eq!(
            parse_version_text("22.7.1").expect("valid"),
            GmpVersion(22, 7)
        );
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(
            parse_version_text(" 22.6 \n").expect("valid"),
            GmpVersion(22, 6)
        );
    }

    #[test]
    fn rejects_invalid_versions() {
        let error = parse_version_text("22").expect_err("invalid");
        assert!(matches!(error, GvmError::XmlParse(_)));
    }

    #[test]
    fn maps_known_supported_versions() {
        assert_eq!(
            map_supported_version(GmpVersion(22, 4)).expect("supported"),
            GmpVersion(22, 4)
        );
        assert_eq!(
            map_supported_version(GmpVersion(22, 7)).expect("supported"),
            GmpVersion(22, 7)
        );
    }

    #[test]
    fn maps_newer_minor_to_next_compatible_version() {
        assert_eq!(
            map_supported_version(GmpVersion(22, 8)).expect("supported"),
            GmpVersion(22, 8)
        );
    }

    #[test]
    fn rejects_unsupported_versions() {
        assert!(matches!(
            map_supported_version(GmpVersion(21, 4)).expect_err("unsupported"),
            GvmError::UnsupportedVersion(21, 4)
        ));
        assert!(matches!(
            map_supported_version(GmpVersion(22, 3)).expect_err("unsupported"),
            GvmError::UnsupportedVersion(22, 3)
        ));
    }
}
