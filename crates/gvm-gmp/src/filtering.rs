// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Shared gvmd filter composition helpers.

/// Pagination inputs for gvmd list-style filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pagination {
    /// 1-based page index requested by the caller.
    pub page: usize,
    /// Number of rows requested per page.
    pub per_page: usize,
}

impl Pagination {
    /// Create a pagination descriptor from a page/per-page pair.
    #[must_use]
    pub fn new(page: usize, per_page: usize) -> Self {
        Self { page, per_page }
    }

    fn gvmd_window(self) -> (usize, usize) {
        let first = self
            .page
            .saturating_sub(1)
            .saturating_mul(self.per_page)
            .saturating_add(1);
        (first, self.per_page)
    }
}

/// Builder for gvmd filter strings that append pagination terms centrally.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaginatedFilter {
    clauses: Vec<String>,
}

impl PaginatedFilter {
    /// Create an empty filter builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one filter clause if it is non-empty after trimming.
    #[must_use]
    pub fn with_clause(mut self, clause: impl AsRef<str>) -> Self {
        let clause = clause.as_ref().trim();
        if !clause.is_empty() {
            self.clauses.push(clause.to_string());
        }
        self
    }

    /// Append an optional caller-supplied filter string.
    #[must_use]
    pub fn with_filter_string(self, filter_string: Option<&str>) -> Self {
        match filter_string {
            Some(filter_string) => self.with_clause(filter_string),
            None => self,
        }
    }

    /// Append gvmd pagination terms derived from a page/per-page pair.
    #[must_use]
    pub fn with_pagination(mut self, pagination: Pagination) -> Self {
        let (first, rows) = pagination.gvmd_window();
        self.clauses.push(format!("first={first} rows={rows}"));
        self
    }

    /// Render the composed filter string, or `None` when no clauses were added.
    #[must_use]
    pub fn build(self) -> Option<String> {
        (!self.clauses.is_empty()).then(|| self.clauses.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::{PaginatedFilter, Pagination};

    #[test]
    fn paginated_filter_skips_empty_inputs() {
        assert_eq!(PaginatedFilter::new().build(), None);
        assert_eq!(
            PaginatedFilter::new()
                .with_clause("   ")
                .with_filter_string(Some(" "))
                .build(),
            None
        );
    }

    #[test]
    fn paginated_filter_supports_prefix_only() {
        assert_eq!(
            PaginatedFilter::new()
                .with_clause("report_id=abc")
                .build()
                .as_deref(),
            Some("report_id=abc")
        );
    }

    #[test]
    fn paginated_filter_supports_filter_only() {
        assert_eq!(
            PaginatedFilter::new()
                .with_filter_string(Some("severity>5"))
                .build()
                .as_deref(),
            Some("severity>5")
        );
    }

    #[test]
    fn paginated_filter_joins_prefix_filter_and_pagination() {
        assert_eq!(
            PaginatedFilter::new()
                .with_clause("report_id=abc")
                .with_filter_string(Some(" severity>5 "))
                .with_pagination(Pagination::new(3, 25))
                .build()
                .as_deref(),
            Some("report_id=abc severity>5 first=51 rows=25")
        );
    }

    #[test]
    fn paginated_filter_handles_later_pages() {
        assert_eq!(
            PaginatedFilter::new()
                .with_pagination(Pagination::new(2, 10))
                .build()
                .as_deref(),
            Some("first=11 rows=10")
        );
    }
}
