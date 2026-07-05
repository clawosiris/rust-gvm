// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Parity tests for the mock server command recognition and coverage metadata.

#![allow(clippy::unwrap_used, missing_docs)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use gvm_mock_server::response_gen::{CommandSupport, COMMAND_COVERAGE, KNOWN_COMMANDS};
use gvm_mock_server::version::{command_available, GmpVersion};

fn collect_rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).expect("read command source dir") {
        let entry = entry.expect("read command source entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn extract_literal_args(source: &str, marker: &str, commands: &mut BTreeSet<String>) {
    let mut remaining = source;
    while let Some(index) = remaining.find(marker) {
        let after_marker = &remaining[index + marker.len()..];
        let Some(end) = after_marker.find('"') else {
            break;
        };
        commands.insert(after_marker[..end].to_string());
        remaining = &after_marker[end + 1..];
    }
}

fn gvm_gmp_command_names() -> BTreeSet<String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let commands_dir = manifest_dir.join("../gvm-gmp/src/commands");
    let mut files = Vec::new();
    collect_rust_files(&commands_dir, &mut files);

    let mut commands = BTreeSet::new();
    for file in files {
        let source = fs::read_to_string(&file).expect("read command source file");
        extract_literal_args(&source, "XmlCommand::new(\"", &mut commands);
        extract_literal_args(&source, "get_report_detail_command(\"", &mut commands);
    }
    commands
}

#[test]
fn known_commands_are_sorted_for_binary_search() {
    assert!(
        KNOWN_COMMANDS
            .windows(2)
            .all(|window| window[0] < window[1]),
        "KNOWN_COMMANDS must stay sorted because is_known_command uses binary_search"
    );
}

#[test]
fn coverage_metadata_matches_known_commands() {
    let known: BTreeSet<_> = KNOWN_COMMANDS.iter().copied().collect();
    let coverage: BTreeSet<_> = COMMAND_COVERAGE.iter().map(|entry| entry.name).collect();

    let missing_coverage: Vec<_> = known.difference(&coverage).copied().collect();
    let unknown_coverage: Vec<_> = coverage.difference(&known).copied().collect();

    assert!(
        missing_coverage.is_empty(),
        "known commands missing coverage metadata: {missing_coverage:?}"
    );
    assert!(
        unknown_coverage.is_empty(),
        "coverage metadata has commands not in KNOWN_COMMANDS: {unknown_coverage:?}"
    );
}

#[test]
fn gvm_gmp_emitted_commands_are_known_and_classified() {
    let emitted = gvm_gmp_command_names();
    let known: BTreeSet<_> = KNOWN_COMMANDS.iter().copied().collect();
    let coverage: BTreeSet<_> = COMMAND_COVERAGE.iter().map(|entry| entry.name).collect();

    let unknown: Vec<_> = emitted
        .iter()
        .filter(|command| !known.contains(command.as_str()))
        .cloned()
        .collect();
    let unclassified: Vec<_> = emitted
        .iter()
        .filter(|command| !coverage.contains(command.as_str()))
        .cloned()
        .collect();

    assert!(
        unknown.is_empty(),
        "gvm-gmp emits commands unknown to the mock server: {unknown:?}"
    );
    assert!(
        unclassified.is_empty(),
        "gvm-gmp emits commands without mock coverage metadata: {unclassified:?}"
    );
}

#[test]
fn version_gated_commands_declare_minimum_version() {
    let missing_min_version: Vec<_> = COMMAND_COVERAGE
        .iter()
        .filter(|entry| !command_available(entry.name, GmpVersion::V22_7))
        .filter(|entry| entry.min_version.is_none())
        .map(|entry| entry.name)
        .collect();
    assert!(
        missing_min_version.is_empty(),
        "version-gated commands missing min_version metadata: {missing_min_version:?}"
    );

    for entry in COMMAND_COVERAGE
        .iter()
        .filter(|entry| entry.min_version.is_some())
    {
        let min_version = entry.min_version.expect("checked above");
        assert!(
            command_available(entry.name, min_version),
            "{} is not available at its declared minimum GMP version {}",
            entry.name,
            min_version
        );
    }
}

#[test]
fn echo_only_commands_are_intentionally_listed() {
    let echo_only: BTreeSet<_> = COMMAND_COVERAGE
        .iter()
        .filter(|entry| entry.support == CommandSupport::EchoOnly)
        .map(|entry| entry.name)
        .collect();

    for expected in [
        "describe_auth",
        "move_task",
        "run_wizard",
        "sync_config",
        "test_alert",
        "verify_report_format",
        "verify_scanner",
    ] {
        assert!(
            echo_only.contains(expected),
            "{expected} should be explicitly documented as echo-only"
        );
    }

    for semantic in [
        "create_asset",
        "get_assets",
        "modify_auth",
        "modify_license",
        "get_timezones",
        "get_credential_stores",
    ] {
        let coverage = COMMAND_COVERAGE
            .iter()
            .find(|entry| entry.name == semantic)
            .expect("semantic command should be classified");
        assert_ne!(
            coverage.support,
            CommandSupport::EchoOnly,
            "{semantic} should not be classified as generic echo behavior"
        );
    }
}
