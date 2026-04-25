# SPDX-License-Identifier: GPL-2.0
#
# devwh audit rebuild -- top-level Makefile.
#
# Usage:
#   # build against the running host kernel (only useful if host is ARM64 Linux):
#   make
#
#   # build against a specific cross-compiled Android kernel tree:
#   make KDIR=$HOME/android-kernel/msm-5.10                       \
#        ARCH=arm64                                               \
#        CROSS_COMPILE=aarch64-linux-gnu-                         \
#        CC=clang LLVM=1 LLVM_IAS=1
#
#   # build for every supported Android kernel in ../kernels/ :
#   make matrix
#
#   make clean
#
# NOTE: the module depends on (a) kallsyms, (b) perf_event hw breakpoints,
# (c) path_mount (5.10+), (d) raw_spin_lock/rwlock_t, and (e) the 4-level
# 4K-page 39/48-bit VA arm64 page-table layout. You MUST rebuild against
# the exact kernel you intend to load it on -- vermagic has to match.

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(CURDIR)

# Where cross-compiled Android kernel sources live (for `make matrix`).
KERNELS_DIR ?= $(PWD)/../kernels
ANDROID_KERNELS ?= 5.4 5.10 5.15 6.1 6.6 6.12

CROSS_COMPILE ?=
ARCH          ?=

.PHONY: all clean help matrix

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules \
		ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) \
		$(if $(LLVM),LLVM=$(LLVM),) \
		$(if $(LLVM_IAS),LLVM_IAS=$(LLVM_IAS),) \
		$(if $(CC),CC=$(CC),)

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -rf build-*

# Per-kernel out-of-tree build, one subdirectory per target.
matrix:
	@for v in $(ANDROID_KERNELS); do                                   \
	    k="$(KERNELS_DIR)/android-$$v";                                \
	    if [ ! -d "$$k" ]; then                                        \
	        echo "[matrix] SKIP android-$$v (no $$k)";                 \
	        continue;                                                  \
	    fi;                                                            \
	    out="build-$$v";                                               \
	    echo "[matrix] === android-$$v ===";                           \
	    rm -rf "$$out"; mkdir -p "$$out";                              \
	    cp -a Kbuild Makefile *.c *.h uapi "$$out/";                   \
	    $(MAKE) -C "$$k" M="$(PWD)/$$out" modules                      \
	        ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-                \
	        CC=clang LLVM=1 LLVM_IAS=1                                 \
	        || { echo "[matrix] FAIL android-$$v"; exit 1; };          \
	    mv "$$out/devwh.ko" "devwh-$$v.ko";                            \
	    echo "[matrix] wrote devwh-$$v.ko";                            \
	done

help:
	@echo "Targets:"
	@echo "  all      - build against \$$KDIR (default: host kernel)"
	@echo "  matrix   - build for every kernel in \$$KERNELS_DIR/android-<ver>"
	@echo "  clean    - clean module build"
	@echo ""
	@echo "Key variables:"
	@echo "  KDIR         = $(KDIR)"
	@echo "  KERNELS_DIR  = $(KERNELS_DIR)"
	@echo "  ANDROID_KERNELS = $(ANDROID_KERNELS)"
