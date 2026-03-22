#!/usr/bin/env bash
set -euo pipefail

export PATH="/usr/local/cargo/bin:${PATH}"
cd /workspace
cargo run --example e2e_gvm_community -- --mode smoke
