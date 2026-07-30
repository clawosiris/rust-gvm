// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]

use std::process::Command;

const BINARY: &str = env!("CARGO_BIN_EXE_gvm-mock-server");

#[test]
fn cli_help_publishes_the_22_7_default() {
    let output = Command::new(BINARY)
        .arg("--help")
        .output()
        .expect("run mock server help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("help is UTF-8");
    assert!(
        stdout.contains("--version <VERSION>") && stdout.contains("[default: 22.7]"),
        "unexpected CLI help: {stdout}"
    );
}
