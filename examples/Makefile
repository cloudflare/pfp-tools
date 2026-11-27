# Copyright (c) 2026 Cloudflare, Inc.
# Licensed under the Apache 2.0 license found in the LICENSE file or at:
#     https://opensource.org/licenses/Apache-2.0
#
# Build, verify, and test the example programs.
#
#   make            compile every example to BPF and run pfp-verifier on it
#   make test       run the native behavior tests
#   make check      both of the above
#
# Requires clang with the BPF target. On macOS, Apple clang does not include
# the BPF target: install LLVM (for example, `brew install llvm@19`) and run
# `make check CLANG=$(brew --prefix llvm@19)/bin/clang TEST_CC=cc`.

CLANG ?= clang
# Compiler for the native behavior tests. Any C compiler with AddressSanitizer
# works, for example Apple clang on macOS.
TEST_CC ?= $(CLANG)
CARGO ?= cargo
HEADERS := ../pfp-headers/include
BUILD := build

# Flags used to compile programs to BPF. These match the flags that Cloudflare
# uses when you upload a program, so code that builds here also builds there.
BPF_CFLAGS ?= -O2 -target bpf -mllvm -bpf-stack-size=8192 -Wall -Werror \
	-fno-gnu-inline-asm -Wformat=2 -Wconversion -Wimplicit-fallthrough \
	-Werror=format-security -nostdlibinc -D__x86_64__ -D__LP64__

# Flags used to compile the native behavior tests.
TEST_CFLAGS ?= -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
	-fno-sanitize-recover=all

EXAMPLES := $(wildcard *.c)
OBJECTS := $(EXAMPLES:%.c=$(BUILD)/%.o)
TESTS := $(wildcard tests/test_*.c)
TEST_BINS := $(TESTS:tests/%.c=$(BUILD)/%)

VERIFIER := ../target/release/pfp-verifier

.PHONY: all verify test check clean

all: verify

check: verify test

$(VERIFIER):
	$(CARGO) build --release --bin pfp-verifier --manifest-path ../Cargo.toml

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: %.c $(wildcard $(HEADERS)/*.h) | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -I $(HEADERS) -c $< -o $@

verify: $(OBJECTS) $(VERIFIER)
	@for obj in $(OBJECTS); do \
		printf '%s: ' "$$obj"; \
		insns=$$($(VERIFIER) "$$obj") || exit 1; \
		echo "verified, $$insns instructions, $$(wc -c < "$$obj" | tr -d ' ') bytes"; \
	done

$(BUILD)/test_%: tests/test_%.c %.c tests/harness.h | $(BUILD)
	$(TEST_CC) $(TEST_CFLAGS) -I $(HEADERS) $< -o $@

test: $(TEST_BINS)
	@for t in $(TEST_BINS); do $$t || exit 1; done

clean:
	rm -rf $(BUILD)
