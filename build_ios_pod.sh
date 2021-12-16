#!/bin/bash

BASEPATH="${PWD}"

echo "Building Dash Shared library..."

cargo lipo --release
cargo build --target=x86_64-apple-ios --release
cargo build --target=aarch64-apple-ios --release
lipo -create target/aarch64-apple-ios/release/libdash_shared_core.a target/x86_64-apple-ios/release/libdash_shared_core.a -output target/universal/release/libdash_shared_core_ios.a

mkdir -p DashSharedCore/lib/ios
mkdir -p DashSharedCore/include

cp -r -p target/universal/release/libdash_shared_core_ios.a DashSharedCore/lib/ios/libdash_shared_core_ios.a
cp -r -p target/dash_shared_core.h DashSharedCore/include