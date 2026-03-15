//! GMP version configuration.

/// Supported GMP versions for the mock server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GmpVersion {
    /// GMP 22.4
    V22_4,
    /// GMP 22.5
    #[default]
    V22_5,
    /// GMP 22.6
    V22_6,
    /// GMP 22.7
    V22_7,
}

impl GmpVersion {
    /// Return the version string as used in GMP responses.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V22_4 => "22.4",
            Self::V22_5 => "22.5",
            Self::V22_6 => "22.6",
            Self::V22_7 => "22.7",
        }
    }
}

impl std::fmt::Display for GmpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
