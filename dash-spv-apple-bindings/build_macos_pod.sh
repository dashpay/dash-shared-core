#!/bin/bash

echo "Building Dash Shared library..."

./check_rust_version.sh
# shellcheck disable=SC2181
if [ $? != 0 ]
then
exit 1
fi
cargo install cargo-lipo

rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin

cargo lipo --release
cargo build --target=x86_64-apple-darwin --release
cargo build --target=aarch64-apple-darwin --release

mkdir -p DashSharedCore/lib/macos
mkdir -p DashSharedCore/include

lipo -create target/x86_64-apple-darwin/release/libdash_shared_core.a target/aarch64-apple-darwin/release/libdash_shared_core.a -output DashSharedCore/lib/macos/libdash_shared_core_macos.a

cp -r -p target/dash_shared_core.h DashSharedCore/include