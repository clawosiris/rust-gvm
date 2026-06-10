// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Shared gvmd filter composition helpers.

use std::fmt;

/// Backend-owned pagination terms that callers must not provide in filter fragments.
pub const PAGINATION_RESERVED_TERMS: &[&str] = &["first", "rows"];

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

/// A validated caller-owned gvmd filter fragment.
///
/// `FilterFragment` rejects backend-owned terms before the fragment is composed
/// with gateway-owned pagination or endpoint scoping clauses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterFragment(String);

impl FilterFragment {
    /// Validate a caller-supplied filter fragment.
    ///
    /// Pagination terms (`first` and `rows`) are always reserved. Pass
    /// endpoint-owned scoping terms such as `report_id` or `task_id` via
    /// `reserved_terms` to reject attempts to override them as well.
    ///
    /// # Errors
    /// Returns [`FilterFragmentError::ReservedTerm`] when the fragment contains
    /// a reserved term key.
    pub fn new(
        fragment: impl Into<String>,
        reserved_terms: &[&str],
    ) -> Result<Self, FilterFragmentError> {
        let fragment = fragment.into();
        let fragment = fragment.trim();
        if let Some(term) = find_reserved_term(fragment, reserved_terms) {
            return Err(FilterFragmentError::ReservedTerm { term });
        }
        Ok(Self(fragment.to_string()))
    }

    /// Borrow the validated fragment.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the fragment and return its inner string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for FilterFragment {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for FilterFragment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors raised while validating a caller-supplied [`FilterFragment`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FilterFragmentError {
    /// The fragment contains a backend- or endpoint-owned term.
    #[error("filter fragment contains reserved term: {term}")]
    ReservedTerm {
        /// The reserved term key found in the fragment.
        term: String,
    },
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

    /// Append an optional trusted filter string without validation.
    ///
    /// This method preserves the original compatibility behavior and does not
    /// reject reserved terms such as `first`, `rows`, or endpoint-owned scoping
    /// terms. Use [`Self::try_with_filter_string`] or [`FilterFragment`] for
    /// untrusted caller-supplied filter fragments.
    #[must_use]
    pub fn with_filter_string(self, filter_string: Option<&str>) -> Self {
        match filter_string {
            Some(filter_string) => self.with_clause(filter_string),
            None => self,
        }
    }

    /// Validate and append an optional caller-supplied filter string.
    ///
    /// Pagination terms (`first` and `rows`) are always reserved. Pass
    /// endpoint-owned scoping terms such as `report_id` or `task_id` via
    /// `reserved_terms` to reject attempts to override them as well.
    ///
    /// # Errors
    /// Returns [`FilterFragmentError::ReservedTerm`] when the filter string
    /// contains a reserved term key.
    pub fn try_with_filter_string(
        self,
        filter_string: Option<&str>,
        reserved_terms: &[&str],
    ) -> Result<Self, FilterFragmentError> {
        match filter_string {
            Some(filter_string) => {
                let fragment = FilterFragment::new(filter_string, reserved_terms)?;
                Ok(self.with_filter_fragment(fragment))
            }
            None => Ok(self),
        }
    }

    /// Append a validated caller-owned filter fragment.
    #[must_use]
    pub fn with_filter_fragment(mut self, fragment: FilterFragment) -> Self {
        let fragment = fragment.as_str();
        if !fragment.is_empty() {
            self.clauses.push(fragment.to_string());
        }
        self
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

fn find_reserved_term(fragment: &str, reserved_terms: &[&str]) -> Option<String> {
    let bytes = fragment.as_bytes();
    let mut index = 0;
    let mut quote = None;
    let mut escaped = false;

    while index < bytes.len() {
        let byte = bytes[index];

        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active_quote {
                quote = None;
            }
            index += 1;
            continue;
        }

        if matches!(byte, b'"' | b'\'') {
            quote = Some(byte);
            index += 1;
            continue;
        }

        if is_key_byte(byte) && is_key_boundary(bytes, index) {
            let start = index;
            index += 1;
            while bytes.get(index).is_some_and(|byte| is_key_byte(*byte)) {
                index += 1;
            }

            let key = &fragment[start..index];
            let operator_index = skip_grouping_and_whitespace(bytes, index);
            if bytes
                .get(operator_index)
                .is_some_and(|byte| is_operator_byte(*byte))
                && is_reserved_key(key, reserved_terms)
            {
                return Some(key.to_string());
            }
            continue;
        }

        index += 1;
    }

    None
}

fn is_reserved_key(key: &str, reserved_terms: &[&str]) -> bool {
    PAGINATION_RESERVED_TERMS
        .iter()
        .chain(reserved_terms.iter())
        .filter_map(|term| {
            let term = term.trim();
            (!term.is_empty()).then_some(term)
        })
        .any(|term| key.eq_ignore_ascii_case(term))
}

fn is_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn is_key_boundary(bytes: &[u8], index: usize) -> bool {
    index == 0 || !is_key_byte(bytes[index - 1])
}

fn skip_grouping_and_whitespace(bytes: &[u8], mut index: usize) -> usize {
    loop {
        let before = index;
        while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        while bytes
            .get(index)
            .is_some_and(|byte| matches!(byte, b')' | b']' | b'}'))
        {
            index += 1;
        }
        if index == before {
            return index;
        }
    }
}

fn is_operator_byte(byte: u8) -> bool {
    matches!(byte, b'=' | b'<' | b'>' | b'~')
}

#[cfg(test)]
mod tests {
    use super::{FilterFragment, FilterFragmentError, PaginatedFilter, Pagination};

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
    fn filter_fragment_accepts_normal_filter_terms() {
        let fragment =
            FilterFragment::new(" severity>5 name~foo ", &["report_id"]).expect("valid filter");

        assert_eq!(fragment.as_str(), "severity>5 name~foo");
    }

    #[test]
    fn filter_fragment_rejects_first_term() {
        assert_eq!(
            FilterFragment::new("severity>5 first=1", &[]).expect_err("reserved term"),
            FilterFragmentError::ReservedTerm {
                term: "first".to_string()
            }
        );
    }

    #[test]
    fn filter_fragment_rejects_reserved_terms_with_spaced_operator() {
        assert_eq!(
            FilterFragment::new("severity>5 first = 1", &[]).expect_err("reserved term"),
            FilterFragmentError::ReservedTerm {
                term: "first".to_string()
            }
        );
    }

    #[test]
    fn filter_fragment_rejects_grouped_reserved_terms() {
        assert_eq!(
            FilterFragment::new("severity>5 (first=1)", &[]).expect_err("reserved term"),
            FilterFragmentError::ReservedTerm {
                term: "first".to_string()
            }
        );
    }

    #[test]
    fn filter_fragment_rejects_grouped_reserved_terms_with_spaced_operator() {
        assert_eq!(
            FilterFragment::new("(rows = 10) severity>5", &[]).expect_err("reserved term"),
            FilterFragmentError::ReservedTerm {
                term: "rows".to_string()
            }
        );
    }

    #[test]
    fn filter_fragment_rejects_grouped_endpoint_scope_terms() {
        assert_eq!(
            FilterFragment::new("(report_id=abc) severity>5", &["report_id"])
                .expect_err("reserved term"),
            FilterFragmentError::ReservedTerm {
                term: "report_id".to_string()
            }
        );
        assert_eq!(
            FilterFragment::new("(task_id = abc) severity>5", &["task_id"])
                .expect_err("reserved term"),
            FilterFragmentError::ReservedTerm {
                term: "task_id".to_string()
            }
        );
    }

    #[test]
    fn filter_fragment_rejects_reserved_terms_inside_unspaced_group_wrappers() {
        assert_eq!(
            FilterFragment::new("not(first=1)", &[]).expect_err("reserved term"),
            FilterFragmentError::ReservedTerm {
                term: "first".to_string()
            }
        );
    }

    #[test]
    fn filter_fragment_rejects_reserved_terms_after_punctuation_boundaries() {
        assert_eq!(
            FilterFragment::new("severity>5,first=1", &[]).expect_err("reserved term"),
            FilterFragmentError::ReservedTerm {
                term: "first".to_string()
            }
        );
        assert_eq!(
            FilterFragment::new("prefix:rows=10", &[]).expect_err("reserved term"),
            FilterFragmentError::ReservedTerm {
                term: "rows".to_string()
            }
        );
    }

    #[test]
    fn filter_fragment_accepts_reserved_text_inside_escaped_double_quotes() {
        let fragment =
            FilterFragment::new(r#"name="a\" first=1" severity>5"#, &[]).expect("valid filter");

        assert_eq!(fragment.as_str(), r#"name="a\" first=1" severity>5"#);
    }

    #[test]
    fn filter_fragment_accepts_reserved_text_inside_escaped_single_quotes() {
        let fragment =
            FilterFragment::new(r#"name='a\' rows=10' severity>5"#, &[]).expect("valid filter");

        assert_eq!(fragment.as_str(), r#"name='a\' rows=10' severity>5"#);
    }

    #[test]
    fn filter_fragment_accepts_grouped_reserved_text_inside_quotes() {
        let fragment = FilterFragment::new(r#"name="(first=1)" comment='(rows = 10)'"#, &[])
            .expect("valid filter");

        assert_eq!(
            fragment.as_str(),
            r#"name="(first=1)" comment='(rows = 10)'"#
        );
    }

    #[test]
    fn filter_fragment_accepts_reserved_terms_as_substrings() {
        let fragment = FilterFragment::new(
            "first_seen=1 rows_total=10 my_report_id=abc",
            &["report_id"],
        )
        .expect("valid filter");

        assert_eq!(
            fragment.as_str(),
            "first_seen=1 rows_total=10 my_report_id=abc"
        );
    }

    #[test]
    fn filter_fragment_rejects_reserved_term_after_quoted_value() {
        assert_eq!(
            FilterFragment::new(r#"name="foo" first=1"#, &[]).expect_err("reserved term"),
            FilterFragmentError::ReservedTerm {
                term: "first".to_string()
            }
        );
    }

    #[test]
    fn filter_fragment_rejects_rows_term() {
        assert_eq!(
            FilterFragment::new("rows=10 severity>5", &[]).expect_err("reserved term"),
            FilterFragmentError::ReservedTerm {
                term: "rows".to_string()
            }
        );
    }

    #[test]
    fn filter_fragment_rejects_endpoint_scope_terms() {
        assert_eq!(
            FilterFragment::new("report_id=abc severity>5", &["report_id"])
                .expect_err("reserved term"),
            FilterFragmentError::ReservedTerm {
                term: "report_id".to_string()
            }
        );
    }

    #[test]
    fn filter_fragment_rejects_reserved_terms_case_insensitively() {
        assert_eq!(
            FilterFragment::new("Rows=10", &[]).expect_err("reserved term"),
            FilterFragmentError::ReservedTerm {
                term: "Rows".to_string()
            }
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
    fn paginated_filter_joins_validated_filter_and_pagination() {
        let fragment = FilterFragment::new(" severity>5 ", &["report_id"]).expect("valid filter");

        assert_eq!(
            PaginatedFilter::new()
                .with_clause("report_id=abc")
                .with_filter_fragment(fragment)
                .with_pagination(Pagination::new(3, 25))
                .build()
                .as_deref(),
            Some("report_id=abc severity>5 first=51 rows=25")
        );
    }

    #[test]
    fn paginated_filter_try_with_filter_string_rejects_reserved_terms() {
        assert_eq!(
            PaginatedFilter::new()
                .try_with_filter_string(Some("first=1"), &[])
                .expect_err("reserved term"),
            FilterFragmentError::ReservedTerm {
                term: "first".to_string()
            }
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
