#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 ACTUAL_PERCENT FLOOR_PERCENT" >&2
    exit 2
fi

actual=$1
floor=$2

awk -v actual="$actual" -v floor="$floor" '
    function valid(value) {
        return value ~ /^[0-9]+([.][0-9]+)?$/
    }
    BEGIN {
        if (!valid(actual) || !valid(floor)) {
            print "coverage values must be non-negative decimal percentages" > "/dev/stderr"
            exit 2
        }
        if ((actual + 0) < (floor + 0)) {
            printf "coverage %.2f%% is below required floor %.2f%%\n", actual, floor > "/dev/stderr"
            exit 1
        }
        printf "coverage %.2f%% meets required floor %.2f%%\n", actual, floor
    }
'
