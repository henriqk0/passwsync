#!/usr/bin/env bash
# Cross-compiles libpasswsync_ffi.so for the Android ABIs and generates the Kotlin bindings
# (007 T137, research R1, R16, R18). Device-build host only: needs rustup with the Android
# targets, the NDK named in android/rust-android.env and a filled cargo cache; nothing is
# downloaded (--frozen --offline). android/verify.sh never calls this script.
#
# usage: ANDROID_NDK_HOME=/path/to/ndk android/build-rust.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
# shellcheck source=/dev/null
source "$here/rust-android.env"

fail() {
    echo "build-rust: $*" >&2
    exit 1
}

ndk=${ANDROID_NDK_HOME:-}
[[ -n $ndk && -d $ndk ]] || fail "set ANDROID_NDK_HOME to the NDK $NDK_REVISION directory"
revision=$(sed -n 's/^Pkg.Revision *= *//p' "$ndk/source.properties" 2>/dev/null || true)
[[ $revision == "$NDK_REVISION" ]] || fail "NDK revision ${revision:-unknown}, expected $NDK_REVISION"

host_tag=linux-x86_64
toolchain="$ndk/toolchains/llvm/prebuilt/$host_tag/bin"
[[ -d $toolchain ]] || fail "no NDK LLVM toolchain at $toolchain"

read -r -a targets <<<"$RUST_TARGETS"
read -r -a abis <<<"$ANDROID_ABIS"
[[ ${#targets[@]} -eq ${#abis[@]} ]] || fail "RUST_TARGETS and ANDROID_ABIS differ in length"

installed=$(rustup target list --installed)
jni="$here/app/src/main/jniLibs"
for i in "${!targets[@]}"; do
    target=${targets[$i]}
    abi=${abis[$i]}
    grep -qx "$target" <<<"$installed" || fail "rust target $target is not installed"
    linker="$toolchain/${target}${ANDROID_MIN_API}-clang"
    [[ -x $linker ]] || fail "no linker $linker"
    upper=$(tr 'a-z-' 'A-Z_' <<<"$target")
    env "CARGO_TARGET_${upper}_LINKER=$linker" \
        "CC_${target//-/_}=$linker" \
        "AR_${target//-/_}=$toolchain/llvm-ar" \
        cargo build --frozen --offline --release --manifest-path "$repo/Cargo.toml" \
        -p "$CRATE" --target "$target"
    mkdir -p "$jni/$abi"
    cp "$repo/target/$target/release/$LIBRARY" "$jni/$abi/$LIBRARY"
    "$toolchain/llvm-strip" --strip-debug "$jni/$abi/$LIBRARY"
done

# Kotlin bindings from the first ABI's library (the metadata is identical for every target).
cargo run --frozen --offline --release --manifest-path "$repo/tools/uniffi-bindgen/Cargo.toml" -- \
    generate --library "$jni/${abis[0]}/$LIBRARY" --language kotlin \
    --config "$repo/tools/uniffi-bindgen/bindgen.toml" \
    --out-dir "$here/app/src/main/kotlin" --no-format
echo "build-rust: ${abis[*]} built, bindings in app/src/main/kotlin"
