#!/bin/bash
export JAVA_HOME=/usr/lib/jvm/jre-1.8.0-openjdk
export JRE_HOME=/usr/lib/jvm/jre
export ANDROID_HOME=/root/tools/android-studio
export PATH

export NDK_HOME=/root/tools/android-ndk-r21e
export LIBCLANG_PATH=$NDK_HOME/toolchains/renderscript/prebuilt/linux-x86_64/lib64/
export ANDROID_NDK_HOME=$NDK_HOME
export NDK=$NDK_HOME
export TOOLCHAIN=$NDK/toolchains/llvm/prebuilt/linux-x86_64
export API=29
export TARGET=armv7a-linux-androideabi

export AR=$TOOLCHAIN/bin/$TARGET-ar
export AS=$TOOLCHAIN/bin/$TARGET-as
export CC=$TOOLCHAIN/bin/$TARGET$API-clang
export CXX=$TOOLCHAIN/bin/$TARGET$API-clang++
export LD=$TOOLCHAIN/bin/$TARGET-ld
export RANLIB=$TOOLCHAIN/bin/$TARGET-ranlib
export STRIP=$TOOLCHAIN/bin/$TARGET-strip
mode=debug

if [ "$1" = "release" ]; then
	mode=release
fi

BASE=`dirname "$0"`
HOST_OS=`uname -s | tr "[:upper:]" "[:lower:]"`
HOST_ARCH=`uname -m | tr "[:upper:]" "[:lower:]"`

export PATH="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_OS-$HOST_ARCH/bin/":$PATH

android_tools="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_OS-$HOST_ARCH/bin"
api=26

#for target in x86_64-linux-android aarch64-linux-android i686-linux-android armv7-linux-androideabi; do
for target in armv7-linux-androideabi; do
	case $target in
        'armv7-linux-androideabi')
			export CC_ARMV7_linux_android="$android_tools/${target}${api}-clang"
			export AR_ARMV7_linux_android="$android_tools/${target}-ar"
			export CARGO_TARGET_ARMV7_LINUX_ANDROID_AR="$android_tools/$target-ar"
			export CARGO_TARGET_ARMV7_LINUX_ANDROID_LINKER="$android_tools/${target}${api}-clang"
			mkdir -p "$BASE/../../jniLibs/armeabi-v7a/"
			case $mode in
				'release')
					cargo build --target $target --manifest-path "$BASE/Cargo.toml" --no-default-features --features "leaf/default-ring" --release
					cp "$BASE/target/$target/release/libleafandroid.so" "$BASE/../../jniLibs/armeabi-v7a/"
					;;
				*)
					cargo build --target $target --manifest-path "$BASE/Cargo.toml" --no-default-features --features "leaf/default-ring"
					cp "$BASE/target/$target/debug/libleafandroid.so" "$BASE/../../jniLibs/armeabi-v7a/"
					;;
			esac
			;;
        'i686-linux-android')
			export CC_x86_64_linux_android="$android_tools/${target}${api}-clang"
			export AR_x86_64_linux_android="$android_tools/${target}-ar"
			export CARGO_TARGET_X86_64_LINUX_ANDROID_AR="$android_tools/$target-ar"
			export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$android_tools/${target}${api}-clang"
			mkdir -p "$BASE/../../jniLibs/x86/"
			case $mode in
				'release')
					cargo build --target $target --manifest-path "$BASE/Cargo.toml" --no-default-features --features "leaf/default-ring" --release
					cp "$BASE/target/$target/release/libleafandroid.so" "$BASE/../../jniLibs/x86/"
					;;
				*)
					cargo build --target $target --manifest-path "$BASE/Cargo.toml" --no-default-features --features "leaf/default-ring"
					cp "$BASE/target/$target/debug/libleafandroid.so" "$BASE/../../jniLibs/x86/"
					;;
			esac
			;;
		'x86_64-linux-android')
			export CC_x86_64_linux_android="$android_tools/${target}${api}-clang"
			export AR_x86_64_linux_android="$android_tools/${target}-ar"
			export CARGO_TARGET_X86_64_LINUX_ANDROID_AR="$android_tools/$target-ar"
			export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$android_tools/${target}${api}-clang"
			mkdir -p "$BASE/../../jniLibs/x86_64/"
			case $mode in
				'release')
					cargo build --target $target --manifest-path "$BASE/Cargo.toml" --no-default-features --features "leaf/default-ring" --release
					cp "$BASE/target/$target/release/libleafandroid.so" "$BASE/../../jniLibs/x86_64/"
					;;
				*)
					cargo build --target $target --manifest-path "$BASE/Cargo.toml" --no-default-features --features "leaf/default-ring"
					cp "$BASE/target/$target/debug/libleafandroid.so" "$BASE/../../jniLibs/x86_64/"
					;;
			esac
			;;
		'aarch64-linux-android')
			export CC_aarch64_linux_android="$android_tools/${target}${api}-clang"
			export AR_aarch64_linux_android="$android_tools/${target}-ar"
			export CARGO_TARGET_AARCH64_LINUX_ANDROID_AR="$android_tools/$target-ar"
			export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$android_tools/${target}${api}-clang"
			mkdir -p "$BASE/../../jniLibs/arm64-v8a/"
			case $mode in
				'release')
					cargo build --target $target --manifest-path "$BASE/Cargo.toml" --no-default-features --features "leaf/default-ring" --release
					cp "$BASE/target/$target/release/libleafandroid.so" "$BASE/../../jniLibs/arm64-v8a/"
					;;
				*)
					cargo build --target $target --manifest-path "$BASE/Cargo.toml" --no-default-features --features "leaf/default-ring"
					cp "$BASE/target/$target/debug/libleafandroid.so" "$BASE/../../jniLibs/arm64-v8a/"
					;;
			esac
			;;
		*)
			echo "Unknown target $target"
			;;
	esac
done
