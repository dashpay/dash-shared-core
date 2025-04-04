#!/bin/bash

set -ex
BUILD_TYPE=${1:-release}  # Default to "release", override with "debug" if passed
if [[ "$BUILD_TYPE" == "release" ]]; then
    BUILD_FLAG="release"
else
    BUILD_FLAG=""
fi

echo "▶ Building Dash Shared Core..."
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
REQUIRED_VERSION=1.85.0
CURRENT_VERSION=$(rustc -V | awk '{sub(/-.*/,"");print $2}')
FRAMEWORK=DashSharedCore
LIB_NAME=dash_spv_apple_bindings
OBJC=false
WRAPPER=objc_wrapper
MIN_IOS=14.0
MIN_MACOS=10.15

echo "▶ rustc -V: current ${CURRENT_VERSION} vs. required ${REQUIRED_VERSION}"
if compare_version "${REQUIRED_VERSION}" "${CURRENT_VERSION}"; then
  echo "❌ERROR: rustc version ${CURRENT_VERSION} not supported, please upgrade to at least ${REQUIRED_VERSION}"
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
cargo lipo --$BUILD_FLAG
build_targets=(
    "x86_64-apple-ios"
    "aarch64-apple-ios"
    "aarch64-apple-ios-sim"
    "x86_64-apple-darwin"
    "aarch64-apple-darwin"

)
export IPHONEOS_DEPLOYMENT_TARGET=$MIN_IOS
export MACOSX_DEPLOYMENT_TARGET=$MIN_MACOS
export RUSTC_LOG=rustc_codegen_ssa::back::link=info

if $OBJC; then
  features="objc"
else
  features=""
fi

for target in "${build_targets[@]}"; do
    echo "▶ Building for $target"
    lib_path="../../target/$target/$BUILD_TYPE/lib${LIB_NAME}.a"
    if [ ! -f "$lib_path" ]; then
      cargo +nightly -Z build-std=std,compiler_builtins build --features="$features" --target="$target" --"$BUILD_FLAG"
    fi
done

wait
mkdir -p target/{framework,include,lib/{ios,ios-simulator,macos}}
./verify_o_set.sh $MIN_IOS ../target
./verify_a_lib.sh $MIN_IOS ../target/x86_64-apple-ios/"$BUILD_TYPE"/lib${LIB_NAME}.a
./verify_a_lib.sh $MIN_IOS ../target/aarch64-apple-ios/"$BUILD_TYPE"/lib${LIB_NAME}.a

lipo -create ../target/x86_64-apple-darwin/"$BUILD_TYPE"/lib${LIB_NAME}.a \
  ../target/aarch64-apple-darwin/"$BUILD_TYPE"/lib${LIB_NAME}.a \
  -output target/lib/macos/lib${LIB_NAME}_macos.a

cp -r -p ../target/aarch64-apple-ios/"$BUILD_TYPE"/lib${LIB_NAME}.a target/lib/ios/lib${LIB_NAME}_ios.a &
lipo -create ../target/x86_64-apple-ios/"$BUILD_TYPE"/lib${LIB_NAME}.a  \
  ../target/aarch64-apple-ios-sim/"$BUILD_TYPE"/lib${LIB_NAME}.a \
  -output target/lib/ios-simulator/lib${LIB_NAME}_ios.a &
wait
wait

if $OBJC; then
  if which clang-format >/dev/null; then
    find target/include -name ${WRAPPER}.h -print0 | xargs -0 clang-format -i -style=file
  else
      echo "❌clang-format not installed, install it by running $(brew install clang-format)"
  fi
fi

#TODO: ferment should be used instead of sed
sed -i '' '/#ifndef/ a\
typedef struct Runtime Runtime;
' target/include/dash_spv_apple_bindings.h

xcodebuild -create-xcframework \
	-library target/lib/ios/lib${LIB_NAME}_ios.a -headers target/include \
	-library target/lib/ios-simulator/lib${LIB_NAME}_ios.a -headers target/include \
	-output target/framework/${FRAMEWORK}.xcframework

./verify_a_lib.sh $MIN_IOS  target/lib/ios/lib${LIB_NAME}_ios.a

echo "✅ Dash Shared Core built successfully"
