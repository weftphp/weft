# Builds, tests and installs weft: the engine (root crate) and the PHP extension (ext/).
#
#   make                 build the PHP extension -> ext/target/release/weft.so
#   make PROFILE=debug   debug build
#   make test            engine tests, then the PHP extension tests
#   make install         copy weft.so into PHP's extension dir
#   make PHP_CONFIG=/path/to/php-config ...   target a different PHP

PROFILE    ?= release
PHP_CONFIG ?= php-config
PHP        ?= php

UNAME := $(shell uname)
ifeq ($(UNAME),Darwin)
LIB := libweft_php.dylib
else
LIB := libweft_php.so
endif

EXT_DIR     := ext
TARGET_DIR  := $(EXT_DIR)/target/$(PROFILE)
SO          := $(TARGET_DIR)/weft.so
CARGO_FLAGS := $(if $(filter release,$(PROFILE)),--release,)

.PHONY: all engine ext test test-engine test-ext install uninstall check fmt clean

all: ext

engine:
	cargo build $(CARGO_FLAGS)

# Cargo decides what needs rebuilding (it tracks the engine sources the extension uses).
ext:
	cd $(EXT_DIR) && PHP_CONFIG=$(PHP_CONFIG) cargo build $(CARGO_FLAGS)
	cp $(TARGET_DIR)/$(LIB) $(SO)

test: test-engine test-ext

test-engine:
	cargo test $(CARGO_FLAGS)

test-ext: ext
	cd $(EXT_DIR) && PHP=$(PHP) tests/run.sh $(PROFILE)

install: ext
	cp $(SO) "$$($(PHP_CONFIG) --extension-dir)/weft.so"
	@echo "Installed. Enable it with: extension=weft"

uninstall:
	rm -f "$$($(PHP_CONFIG) --extension-dir)/weft.so"

check:
	cargo fmt --all --check
	cargo clippy --all-targets -- -D warnings
	cd $(EXT_DIR) && cargo fmt --check
	cd $(EXT_DIR) && PHP_CONFIG=$(PHP_CONFIG) cargo clippy -- -D warnings

fmt:
	cargo fmt --all
	cd $(EXT_DIR) && cargo fmt

clean:
	cargo clean
	cd $(EXT_DIR) && cargo clean
