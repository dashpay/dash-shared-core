#!/bin/bash

BASEPATH="${PWD}"

echo "Building Dash Shared library..."

rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin

cargo lipo --release
cargo build --target=x86_64-apple-darwin --release
lipo -create target/x86_64-apple-darwin/release/libdash_shared_core.a -output target/universal/release/libdash_shared_core_macos.a

mkdir -p DashSharedCore/lib/macos
mkdir -p DashSharedCore/include

cp -r -p target/universal/release/libdash_shared_core_macos.a DashSharedCore/lib/macos/libdash_shared_core_macos.a
cp -r -p target/dash_shared_core.h DashSharedCore/include
