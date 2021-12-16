#!/bin/bash

BASEPATH="${PWD}"

echo "Building Dash Shared library..."

rm -r DashSharedCore/framework
rm -r DashSharedCore/lib/ios
rm -r DashSharedCore/lib/ios-simulator

cargo lipo --release
cargo build --target=x86_64-apple-ios --release
cargo build --target=aarch64-apple-ios --release

mkdir -p DashSharedCore/framework
mkdir -p DashSharedCore/lib/ios
mkdir -p DashSharedCore/lib/ios-simulator
mkdir -p DashSharedCore/include

cp -r -p target/x86_64-apple-ios/release/libdash_shared_core.a DashSharedCore/lib/ios-simulator/libdash_shared_core_ios.a
cp -r -p target/aarch64-apple-ios/release/libdash_shared_core.a DashSharedCore/lib/ios/libdash_shared_core_ios.a
cp -r -p target/dash_shared_core.h DashSharedCore/include

xcodebuild -create-xcframework \
	-library DashSharedCore/lib/ios/libdash_shared_core_ios.a -headers DashSharedCore/include \
	-library DashSharedCore/lib/ios-simulator/libdash_shared_core_ios.a -headers DashSharedCore/include \
	-output DashSharedCore/framework/DashSharedCore.xcframework
