IOS_DEVICE_TARGET := aarch64-apple-ios
IOS_SIM_TARGETS := aarch64-apple-ios-sim x86_64-apple-ios
RUSTUP ?= rustup
RUST_TOOLCHAIN ?= stable
RUST_TOOLCHAIN_BIN := $(shell dirname "$$($(RUSTUP) which --toolchain $(RUST_TOOLCHAIN) rustc)")
CARGO ?= $(RUST_TOOLCHAIN_BIN)/cargo
CARGO_ENV := PATH="$(RUST_TOOLCHAIN_BIN):$(PATH)"

ios:
	$(CARGO_ENV) $(CARGO) build --release -p leaf-ffi --target $(IOS_DEVICE_TARGET)
	$(CARGO_ENV) $(CARGO) build --release -p leaf-ffi --target aarch64-apple-ios-sim
	$(CARGO_ENV) $(CARGO) build --release -p leaf-ffi --target x86_64-apple-ios
	mkdir -p target/ios/release/iphoneos target/ios/release/iphonesimulator
	cp target/$(IOS_DEVICE_TARGET)/release/libleaf.a target/ios/release/iphoneos/libleaf.a
	lipo -create target/aarch64-apple-ios-sim/release/libleaf.a target/x86_64-apple-ios/release/libleaf.a -output target/ios/release/iphonesimulator/libleaf.a
	if command -v cbindgen >/dev/null 2>&1; then \
		cbindgen --config leaf-ffi/cbindgen.toml leaf-ffi/src/lib.rs > target/ios/release/leaf.h; \
	elif [ -f target/universal/release/leaf.h ]; then \
		cp target/universal/release/leaf.h target/ios/release/leaf.h; \
	else \
		echo "cbindgen not found and no cached target/universal/release/leaf.h exists"; \
		exit 1; \
	fi

ios-dev:
	$(CARGO_ENV) $(CARGO) build -p leaf-ffi --target $(IOS_DEVICE_TARGET)
	$(CARGO_ENV) $(CARGO) build -p leaf-ffi --target aarch64-apple-ios-sim
	$(CARGO_ENV) $(CARGO) build -p leaf-ffi --target x86_64-apple-ios
	mkdir -p target/ios/debug/iphoneos target/ios/debug/iphonesimulator
	cp target/$(IOS_DEVICE_TARGET)/debug/libleaf.a target/ios/debug/iphoneos/libleaf.a
	lipo -create target/aarch64-apple-ios-sim/debug/libleaf.a target/x86_64-apple-ios/debug/libleaf.a -output target/ios/debug/iphonesimulator/libleaf.a
	if command -v cbindgen >/dev/null 2>&1; then \
		cbindgen --config leaf-ffi/cbindgen.toml leaf-ffi/src/lib.rs > target/ios/debug/leaf.h; \
	elif [ -f target/universal/debug/leaf.h ]; then \
		cp target/universal/debug/leaf.h target/ios/debug/leaf.h; \
	else \
		echo "cbindgen not found and no cached target/universal/debug/leaf.h exists"; \
		exit 1; \
	fi

ios-opt:
	$(CARGO_ENV) $(CARGO) build --release -p leaf-ffi --target $(IOS_DEVICE_TARGET) --no-default-features --features "default-openssl"
	mkdir -p target/ios/release/iphoneos
	cp target/$(IOS_DEVICE_TARGET)/release/libleaf.a target/ios/release/iphoneos/libleaf.a
	if command -v cbindgen >/dev/null 2>&1; then \
		cbindgen --config leaf-ffi/cbindgen.toml leaf-ffi/src/lib.rs > target/ios/release/leaf.h; \
	elif [ -f target/universal/release/leaf.h ]; then \
		cp target/universal/release/leaf.h target/ios/release/leaf.h; \
	else \
		echo "cbindgen not found and no cached target/universal/release/leaf.h exists"; \
		exit 1; \
	fi

lib:
	$(CARGO_ENV) $(CARGO) build -p leaf-ffi --release
	cbindgen --config leaf-ffi/cbindgen.toml leaf-ffi/src/lib.rs > target/release/leaf.h
android:
	cargo ndk -t armeabi-v7a -t x86 -t x86_64 -t arm64-v8a build --release -p leaf-ffi
	cbindgen --config leaf-ffi/cbindgen.toml leaf-ffi/src/lib.rs > target/universal/release/leaf.h
lib-dev:
	cargo build -p leaf-ffi
	cbindgen --config leaf-ffi/cbindgen.toml leaf-ffi/src/lib.rs > target/debug/leaf.h

local:
	cargo build -p leaf-bin --release

local-dev:
	cargo build -p leaf-bin

mipsel:
	./misc/build_cross.sh mipsel-unknown-linux-musl

mips:
	./misc/build_cross.sh mips-unknown-linux-musl

test:
	cargo test -p leaf -- --nocapture

# Force a re-generation of protobuf files.
proto-gen:
	touch leaf/build.rs
	PROTO_GEN=1 cargo build -p leaf
