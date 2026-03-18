// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Shared GMP usage-type values.

/// GMP usage types for tasks, configs, and reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum UsageType {
    /// Standard scan resources.
    #[default]
    Scan,
    /// Audit resources.
    Audit,
    /// Policy resources.
    Policy,
}

impl UsageType {
    /// Returns the GMP wire-format string for this value.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Audit => "audit",
            Self::Policy => "policy",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::UsageType;

    #[test]
    fn usage_type_variants_map_to_wire_values() {
        assert_eq!(UsageType::Scan.as_gmp_str(), "scan");
        assert_eq!(UsageType::Audit.as_gmp_str(), "audit");
        assert_eq!(UsageType::Policy.as_gmp_str(), "policy");
    }
}
