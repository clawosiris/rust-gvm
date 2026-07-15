// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Audit a public gvmd GMP.xml.in file against the qualified command registry.

#![allow(clippy::print_stdout, missing_docs)]

use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

use gvm_gmp::capabilities::{GvmdEvidence, COMMAND_CAPABILITIES};
use quick_xml::events::Event;
use quick_xml::Reader;

fn schema_commands(path: &Path) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let mut reader = Reader::from_reader(BufReader::new(File::open(path)?));
    reader.config_mut().trim_text(true);

    let mut buffer = Vec::new();
    let mut commands = BTreeSet::new();
    let mut depth = 0_usize;
    let mut in_top_level_command = false;
    let mut capture_name = false;

    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(element) => {
                if depth == 1 && element.name().as_ref() == b"command" {
                    in_top_level_command = true;
                } else if in_top_level_command && depth == 2 && element.name().as_ref() == b"name" {
                    capture_name = true;
                }
                depth += 1;
            }
            Event::Text(text) if capture_name => {
                commands.insert(text.decode()?.into_owned());
            }
            Event::End(element) => {
                depth = depth.saturating_sub(1);
                if element.name().as_ref() == b"name" {
                    capture_name = false;
                } else if depth == 1 && element.name().as_ref() == b"command" {
                    in_top_level_command = false;
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }

    Ok(commands)
}

fn main() -> Result<(), Box<dyn Error>> {
    // The argument selects a local input file; it is not used as a security
    // identity or trusted executable path.
    // nosemgrep: rust.lang.security.args.args
    let path = env::args().nth(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: cargo run -p gvm-gmp --example audit_gmp_schema -- /path/to/GMP.xml.in",
        )
    })?;
    let schema = schema_commands(Path::new(&path))?;
    let expected: BTreeSet<_> = COMMAND_CAPABILITIES
        .iter()
        .filter(|capability| capability.gvmd_evidence == GvmdEvidence::PinnedSchema)
        .map(|capability| capability.name.to_string())
        .collect();

    let schema_only: Vec<_> = schema.difference(&expected).cloned().collect();
    let registry_only: Vec<_> = expected.difference(&schema).cloned().collect();

    if !schema_only.is_empty() || !registry_only.is_empty() {
        return Err(io::Error::other(format!(
            "GMP schema drift detected; schema-only={schema_only:?}, registry-only={registry_only:?}"
        ))
        .into());
    }

    println!(
        "GMP schema audit passed: {} qualified schema commands match {}",
        schema.len(),
        Path::new(&path).display()
    );
    Ok(())
}
