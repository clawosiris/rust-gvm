// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Parity check against a command snapshot extracted from public gvmd GMP.xml.in.

#![allow(clippy::unwrap_used, missing_docs)]

use std::collections::BTreeSet;

use gvm_gmp::capabilities::{GvmdEvidence, MockSupport, COMMAND_CAPABILITIES};
use gvm_gmp::GmpVersion;

const PINNED_COMMANDS: &str = include_str!("data/gvmd-gmp-commands-fb21137.txt");

fn pinned_commands() -> BTreeSet<&'static str> {
    PINNED_COMMANDS
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

#[test]
fn pinned_schema_matches_qualified_registry() {
    let pinned = pinned_commands();
    let documented: BTreeSet<_> = COMMAND_CAPABILITIES
        .iter()
        .filter(|capability| capability.gvmd_evidence == GvmdEvidence::PinnedSchema)
        .map(|capability| capability.name)
        .collect();

    let schema_only: Vec<_> = pinned.difference(&documented).copied().collect();
    let registry_only: Vec<_> = documented.difference(&pinned).copied().collect();

    assert!(
        schema_only.is_empty(),
        "pinned GMP.xml.in commands missing from the registry: {schema_only:?}"
    );
    assert!(
        registry_only.is_empty(),
        "commands marked PinnedSchema but absent from pinned GMP.xml.in: {registry_only:?}"
    );
    assert_eq!(pinned.len(), 152);
}

#[test]
fn non_schema_qualifications_are_absent_from_pinned_schema() {
    let pinned = pinned_commands();

    for capability in COMMAND_CAPABILITIES
        .iter()
        .filter(|capability| capability.gvmd_evidence != GvmdEvidence::PinnedSchema)
    {
        assert!(
            !pinned.contains(capability.name),
            "{} is now in the schema; update its evidence qualification",
            capability.name
        );
    }
}

#[test]
fn published_matrix_counts_are_registry_derived() {
    let matrix_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/SUPPORT_MATRIX.md");
    let Ok(matrix) = std::fs::read_to_string(matrix_path) else {
        // The workspace-level matrix is intentionally absent from the
        // published gvm-gmp package; this consistency check is workspace-only.
        return;
    };

    for (version, label, client, mock) in [
        (GmpVersion(22, 4), "22.4", "Gmp224", "V22_4"),
        (GmpVersion(22, 5), "22.5", "Gmp225", "V22_5"),
        (GmpVersion(22, 6), "22.6", "Gmp226", "V22_6"),
        (GmpVersion(22, 7), "22.7", "Gmp227", "V22_7"),
        (GmpVersion(22, 8), "22.8 and newer", "GmpNext", "V22_8"),
    ] {
        let count = COMMAND_CAPABILITIES
            .iter()
            .filter(|capability| capability.available_in(version))
            .count();
        assert!(
            matrix.contains(&format!("| {label} | `{client}` | {count} | `{mock}` |")),
            "support matrix is missing the derived {label} count {count}"
        );
    }

    for (support, label) in [
        (MockSupport::Stateful, "Stateful mock behavior"),
        (MockSupport::Fixture, "Fixture mock behavior"),
        (MockSupport::EchoOnly, "Echo-only mock behavior"),
    ] {
        let count = COMMAND_CAPABILITIES
            .iter()
            .filter(|capability| capability.support == support)
            .count();
        assert!(
            matrix.contains(&format!("| {label} | {count} |")),
            "support matrix is missing the derived {label} count {count}"
        );
    }
}
