#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
check="$script_dir/check_coverage_threshold.sh"
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

# shellcheck source=../.config/coverage.env
. "$repo_root/.config/coverage.env"
below_floor=$(awk -v floor="$RUST_COVERAGE_FLOOR" 'BEGIN { printf "%.2f", floor - 0.01 }')

"$check" "$RUST_COVERAGE_FLOOR" "$RUST_COVERAGE_FLOOR" >/dev/null

if "$check" "$below_floor" "$RUST_COVERAGE_FLOOR" >/dev/null 2>&1; then
    echo "below-floor coverage unexpectedly passed" >&2
    exit 1
fi

echo "controlled below-floor coverage value was rejected"
