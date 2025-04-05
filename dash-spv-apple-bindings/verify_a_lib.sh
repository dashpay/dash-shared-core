#!/bin/bash
# This script unarchives resulting .a lib and inspects the deployment targets of object files in a static library (.a) file.
MIN_VERSION=$1
LIB_PATH=$2

mkdir -p tmp && cd tmp || exit

# 1. Extract object files from .a
ar -x ../"$LIB_PATH"

# 2. Inspect deployment targets with vtool
for obj in *.o; do
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
cd ..
rm -rf tmp
