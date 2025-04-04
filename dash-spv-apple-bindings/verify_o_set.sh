#!/bin/bash
# This script inspects the deployment targets of object files in a static library (.a) file.
MIN_VERSION=$1
BUILD_DIR=$2

# 2. Inspect deployment targets with vtool
find "$BUILD_DIR" -type f -name '*.o' | while read -r obj; do
    vtool -show-build "$obj" | awk -v min_required="$MIN_VERSION" '
    /^[^[:space:]]+\.o:$/ {
        current_file = $0
    }
    /minos|version[[:space:]]+[0-9]+\.[0-9]+/ {
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^[0-9]+\.[0-9]+$/) {
                if ($i > min_required) {
                    print current_file " -> " $i
                }
            }
        }
    }
    '
done
