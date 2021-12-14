#!/bin/bash

# build iOS & MacOS binaries
cargo +nightly lipo --release
cargo +nightly build --target=x86_64-apple-darwin --release
cargo +nightly build --target=aarch64-apple-darwin --release
lipo -create target/aarch64-apple-darwin/release/libdash_shared_core.a target/x86_64-apple-darwin/release/libdash_shared_core.a -output target/universal/release/libdash_shared_core_macos.a

# Assume we have structure like this:
# dash/dash-shared-core/...
# dash/DashSync/...
cp -p target/universal/release/libdash_shared_core_macos.a ../DashSync/DashSync/lib/libdash_shared_core_macos.a
cp -p target/universal/release/libdash_shared_core.a ../DashSync/DashSync/lib/libdash_shared_core_ios.a
cp -p target/dash_shared_core.h ../DashSync/DashSync/shared/crypto/
