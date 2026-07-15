// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Audit a public gvmd GMP.xml.in file against the qualified command registry.

#![allow(clippy::print_stdout, missing_docs)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use clap::Parser;
use gvm_gmp::capabilities::{GvmdEvidence, COMMAND_CAPABILITIES};
use quick_xml::events::Event;
use quick_xml::Reader;

#[derive(Debug, Parser)]
#[command(about = "Audit a public gvmd GMP.xml.in against the command registry")]
struct Args {
    /// Path to the public gvmd GMP.xml.in file to audit.
    schema: PathBuf,
}

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
    let args = Args::parse();
    let schema = schema_commands(&args.schema)?;
    let expected: BTreeSet<_> = COMMAND_CAPABILITIES
        .iter()
        .filter(|capability| capability.gvmd_evidence == GvmdEvidence::PinnedSchema)
        .map(|capability| capability.name.to_string())
        .collect();

    let schema_only: Vec<_> = schema.difference(&expected).cloned().collect();
    let registry_only: Vec<_> = expected.difference(&schema).cloned().collect();

    if !schema_only.is_empty() || !registry_only.is_empty() {
        return Err(std::io::Error::other(format!(
            "GMP schema drift detected; schema-only={schema_only:?}, registry-only={registry_only:?}"
        ))
        .into());
    }

    println!(
        "GMP schema audit passed: {} qualified schema commands match {}",
        schema.len(),
        args.schema.display()
    );
    Ok(())
}
