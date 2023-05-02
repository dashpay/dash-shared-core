#!/bin/bash

echo "Building Dash Shared Core..."

compare_version() {
    if [[ $1 == $2 ]]; then
        return 1
    fi
    local IFS=.
    local i a=(${1%%[^0-9.]*}) b=(${2%%[^0-9.]*})
    local arem=${1#${1%%[^0-9.]*}} brem=${2#${2%%[^0-9.]*}}
    for ((i=0; i<${#a[@]} || i<${#b[@]}; i++)); do
        if ((10#${a[i]:-0} < 10#${b[i]:-0})); then
            return 1
        elif ((10#${a[i]:-0} > 10#${b[i]:-0})); then
            return 0
        fi
    done
    if [ "$arem" '<' "$brem" ]; then
        return 1
    elif [ "$arem" '>' "$brem" ]; then
        return 0
    fi
    return 1
}
REQUIRED_VERSION=1.66.0
CURRENT_VERSION=$(rustc -V | awk '{sub(/-.*/,"");print $2}')
echo "rustc -V: current ${CURRENT_VERSION} vs. required ${REQUIRED_VERSION}"
if compare_version "${REQUIRED_VERSION}" "${CURRENT_VERSION}"; then
  echo "ERROR: rustc version ${CURRENT_VERSION} not supported, please upgrade to at least ${REQUIRED_VERSION}"
  exit 1
fi

cargo install cargo-lipo

# macOS
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin

cargo lipo --release
cargo build --target=x86_64-apple-darwin --release
cargo build --target=aarch64-apple-darwin --release

mkdir -p DashSharedCore/lib/macos
mkdir -p DashSharedCore/include

lipo -create target/x86_64-apple-darwin/release/libdash_shared_core.a target/aarch64-apple-darwin/release/libdash_shared_core.a -output DashSharedCore/lib/macos/libdash_shared_core_macos.a

cp -r -p target/dash_shared_core.h DashSharedCore/include

# iOS

rm -r DashSharedCore/framework
rm -r DashSharedCore/lib/ios
rm -r DashSharedCore/lib/ios-simulator

rustup target add x86_64-apple-ios
rustup target add aarch64-apple-ios
rustup target add aarch64-apple-ios-sim

cargo lipo --release
cargo build --target=x86_64-apple-ios --release
cargo build --target=aarch64-apple-ios --release
cargo build --target=aarch64-apple-ios-sim --release

mkdir -p DashSharedCore/framework
mkdir -p DashSharedCore/lib/ios
mkdir -p DashSharedCore/lib/ios-simulator
mkdir -p DashSharedCore/include

cp -r -p target/x86_64-apple-ios/release/libdash_shared_core.a DashSharedCore/lib/ios-simulator/libdash_shared_core_ios_x86_64.a
cp -r -p target/aarch64-apple-ios/release/libdash_shared_core.a DashSharedCore/lib/ios/libdash_shared_core_ios.a
cp -r -p target/aarch64-apple-ios-sim/release/libdash_shared_core.a DashSharedCore/lib/ios-simulator/libdash_shared_core_ios_arm.a
cp -r -p target/dash_shared_core.h DashSharedCore/include

lipo -create DashSharedCore/lib/ios-simulator/libdash_shared_core_ios_arm.a DashSharedCore/lib/ios-simulator/libdash_shared_core_ios_x86_64.a \
  -output DashSharedCore/lib/ios-simulator/libdash_shared_core_ios.a

xcodebuild -create-xcframework \
	-library DashSharedCore/lib/ios/libdash_shared_core_ios.a -headers DashSharedCore/include \
	-library DashSharedCore/lib/ios-simulator/libdash_shared_core_ios.a -headers DashSharedCore/include \
	-output DashSharedCore/framework/DashSharedCore.xcframework

echo "Done building Dash Shared Core"
