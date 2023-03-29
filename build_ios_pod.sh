#!/bin/bash

echo "Building Dash Shared library..."

./check_rust_version.sh
# shellcheck disable=SC2181
if [ $? != 0 ]
then
exit 1
fi
cargo install cargo-lipo

rm -r DashSharedCore/framework
rm -r DashSharedCore/lib/ios
rm -r DashSharedCore/lib/ios-simulator

#rustup target add x86_64-apple-ios
rustup target add aarch64-apple-ios
rustup target add aarch64-apple-ios-sim

#cargo lipo --release
cargo lipo --release --targets aarch64-apple-ios
#cargo build --target=x86_64-apple-ios --release
cargo build --target=aarch64-apple-ios --release
cargo build --target=aarch64-apple-ios-sim --release

mkdir -p DashSharedCore/framework
mkdir -p DashSharedCore/lib/ios
mkdir -p DashSharedCore/lib/ios-simulator
mkdir -p DashSharedCore/include

#cp -r -p target/x86_64-apple-ios/release/libdash_shared_core.a DashSharedCore/lib/ios-simulator/libdash_shared_core_ios_x86_64.a
cp -r -p target/aarch64-apple-ios/release/libdash_shared_core.a DashSharedCore/lib/ios/libdash_shared_core_ios.a
cp -r -p target/aarch64-apple-ios-sim/release/libdash_shared_core.a DashSharedCore/lib/ios-simulator/libdash_shared_core_ios_arm.a
cp -r -p target/dash_shared_core.h DashSharedCore/include

#lipo -create DashSharedCore/lib/ios-simulator/libdash_shared_core_ios_arm.a DashSharedCore/lib/ios-simulator/libdash_shared_core_ios_x86_64.a -output DashSharedCore/lib/ios-simulator/libdash_shared_core_ios.a
lipo -create DashSharedCore/lib/ios-simulator/libdash_shared_core_ios_arm.a -output DashSharedCore/lib/ios-simulator/libdash_shared_core_ios.a

xcodebuild -create-xcframework \
	-library DashSharedCore/lib/ios/libdash_shared_core_ios.a -headers DashSharedCore/include \
	-library DashSharedCore/lib/ios-simulator/libdash_shared_core_ios.a -headers DashSharedCore/include \
	-output DashSharedCore/framework/DashSharedCore.xcframework

echo "Done building for ios"
