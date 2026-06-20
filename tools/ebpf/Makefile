# Build the BPF exec-guard program and copy it where the Rust build can embed it.
#
# Prerequisites:
#   apt install clang llvm linux-headers-$(uname -r) libbpf-dev
#
# Usage:
#   make -C tools/ebpf
#   make -C tools/ebpf clean

CLANG     ?= clang
LLC       ?= llc
STRIP     ?= llvm-strip
ARCH      ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERN_HDRS ?= /usr/include
OUT       := ../../crates/babbleon/src/enforcement/bpf_objects

.PHONY: all clean check-deps

all: check-deps $(OUT)/exec_guard.bpf.o

$(OUT):
	mkdir -p $@

$(OUT)/exec_guard.bpf.o: exec_guard.bpf.c | $(OUT)
	$(CLANG) -O2 -target bpf \
	    -D__TARGET_ARCH_$(ARCH) \
	    -I$(KERN_HDRS) \
	    -I$(KERN_HDRS)/bpf \
	    -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types \
	    -c $< -o $@
	$(STRIP) -g $@
	@echo "Built: $@"
	@echo "Embed this in Rust with: include_bytes!(\"bpf_objects/exec_guard.bpf.o\")"

check-deps:
	@which $(CLANG) > /dev/null 2>&1 || \
	    (echo "ERROR: clang not found. Install: apt install clang" && exit 1)
	@test -f $(KERN_HDRS)/bpf/bpf_helpers.h || \
	    (echo "ERROR: libbpf headers not found. Install: apt install libbpf-dev" && exit 1)

clean:
	rm -f $(OUT)/exec_guard.bpf.o
