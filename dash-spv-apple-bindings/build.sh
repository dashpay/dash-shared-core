#!/bin/bash

set -ex

echo "Building Dash Shared Core..."
pwd

compare_version() {
     # shellcheck disable=SC2053
   if [[ $1 == $2 ]]; then
        return 1
    fi
    local IFS=.
    # shellcheck disable=SC2206
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
REQUIRED_VERSION=1.80.1
CURRENT_VERSION=$(rustc -V | awk '{sub(/-.*/,"");print $2}')
FRAMEWORK=DashSharedCore
LIB_NAME=dash_spv_apple_bindings
WRAPPER=objc_wrapper

echo "rustc -V: current ${CURRENT_VERSION} vs. required ${REQUIRED_VERSION}"
if compare_version "${REQUIRED_VERSION}" "${CURRENT_VERSION}"; then
  echo "ERROR: rustc version ${CURRENT_VERSION} not supported, please upgrade to at least ${REQUIRED_VERSION}"
  exit 1
fi

#cargo clean && cargo update
cargo install cargo-lipo
for target in "x86_64-apple-darwin" "aarch64-apple-darwin" "x86_64-apple-ios" "aarch64-apple-ios" "aarch64-apple-ios-sim"; do
    if ! rustup target list | grep -q "${target} (installed)"; then
        rustup target add "$target"
    fi
done

rm -rf target/{framework,include,lib}
cargo lipo
#cargo lipo --release
build_targets=(
    "x86_64-apple-ios"
    "aarch64-apple-ios"
    "aarch64-apple-ios-sim"
    "x86_64-apple-darwin"
    "aarch64-apple-darwin"

)
for target in "${build_targets[@]}"; do
    if [ ! -f "../../target/$target/release/lib${LIB_NAME}.a" ]; then
        cargo build --target="$target" --features=objc &
#        cargo build --target="$target" --features=objc --release &
    fi
done
wait
mkdir -p target/{framework,include,lib/{ios,ios-simulator,macos}}

lipo -create ../target/x86_64-apple-darwin/release/lib${LIB_NAME}.a \
  ../target/aarch64-apple-darwin/release/lib${LIB_NAME}.a \
  -output target/lib/macos/lib${LIB_NAME}_macos.a &
cp -r -p ../target/aarch64-apple-ios/release/lib${LIB_NAME}.a target/lib/ios/lib${LIB_NAME}_ios.a &
lipo -create ../target/x86_64-apple-ios/release/lib${LIB_NAME}.a  \
  ../target/aarch64-apple-ios-sim/release/lib${LIB_NAME}.a \
  -output target/lib/ios-simulator/lib${LIB_NAME}_ios.a &
wait
wait

if which clang-format >/dev/null; then
  find target/include -name ${WRAPPER}.h -print0 | xargs -0 clang-format -i -style=file
else
    echo "warning: clang-format not installed, install it by running $(brew install clang-format)"
fi
sed -i '' '/#ifndef/ a\
typedef struct Runtime Runtime;
' target/include/dash_shared_core.h

xcodebuild -create-xcframework \
	-library target/lib/ios/lib${LIB_NAME}_ios.a -headers target/include \
	-library target/lib/ios-simulator/lib${LIB_NAME}_ios.a -headers target/include \
	-output target/framework/${FRAMEWORK}.xcframework \
#	IPHONEOS_DEPLOYMENT_TARGET=15.6

echo "Done building Dash Shared Core"
