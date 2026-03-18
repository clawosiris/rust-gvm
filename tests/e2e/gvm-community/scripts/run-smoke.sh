#!/usr/bin/env bash
set -euo pipefail

cd /workspace
cargo run --example e2e_gvm_community -- --mode smoke
