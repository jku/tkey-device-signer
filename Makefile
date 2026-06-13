# Check for OS, if not macos assume linux
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	shasum = shasum -a 512
else
	shasum = sha512sum
endif

IMAGE=ghcr.io/tillitis/tkey-builder:5rc1

OBJCOPY ?= llvm-objcopy

P := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
LIBDIR ?= $(P)/../tkey-libs

CC = clang

INCLUDE = $(LIBDIR)/include

# If you want libcommon's debug_puts() et cetera to output something
# on the QEMU debug port, use -DQEMU_DEBUG, or -DTKEY_DEBUG if you
# want it on the TKey HID debug endpoint
CFLAGS = -target riscv32-unknown-none-elf -march=rv32iczmmul -mabi=ilp32 -mcmodel=medany \
   -static -std=gnu99 -O2 -ffast-math -fno-common -fno-builtin-printf \
   -fno-builtin-putchar -nostdlib -mno-relax -flto -g \
   -Wall -Werror=implicit-function-declaration \
   -I $(INCLUDE) -I $(LIBDIR) #-DTKEY_DEBUG #-DQEMU_DEBUG

MLDSADIR ?= $(P)/../mldsa-native
CFLAGS += -I signer -I signer/mock-includes -I $(MLDSADIR)/mldsa -I $(MLDSADIR)/mldsa/src -DMLD_CONFIG_FILE=\"mldsa_config.h\"

ifneq ($(TKEY_SIGNER_APP_NO_TOUCH),)
CFLAGS := $(CFLAGS) -DTKEY_SIGNER_APP_NO_TOUCH
endif

AS = clang
ASFLAGS = -target riscv32-unknown-none-elf -march=rv32iczmmul -mabi=ilp32 -mcmodel=medany -mno-relax

LDFLAGS=-T $(LIBDIR)/app.lds -L $(LIBDIR) -lcommon -lcrt0


.PHONY: all
all: signer/app-ed25519.bin signer/app-mldsa.bin check-signer-hash

# Create compile_commands.json for clangd and LSP
.PHONY: clangd
clangd: compile_commands.json
compile_commands.json:
	$(MAKE) clean
	bear -- make signer/app-ed25519.bin signer/app-mldsa.bin

# Turn elf into bin for device
%.bin: %.elf
	$(OBJCOPY) --input-target=elf32-littleriscv --output-target=binary $^ $@
	chmod a-x $@

show-hashes: signer/app-ed25519.bin signer/app-mldsa.bin
	@echo "Device app digests:"
	@$(shasum) signer/app-ed25519.bin signer/app-mldsa.bin

check-signer-hash: signer/app-ed25519.bin signer/app-mldsa.bin show-hashes
	@$(shasum) -c signer/apps.sha512

CLANG_TIDY = clang-tidy

.PHONY: check
check:
	$(CLANG_TIDY) -header-filter=.* -checks=cert-* signer/*.[ch] -- $(CFLAGS)

SIGNEROBJS_COMMON = signer/app_proto.o
SIGNEROBJS_MLDSA = signer/main_mldsa.o signer/backend_mldsa.o $(SIGNEROBJS_COMMON) signer/mldsa_native.o
SIGNEROBJS_ED25519 = signer/main_ed25519.o signer/backend_ed25519.o $(SIGNEROBJS_COMMON)

signer/main_mldsa.o: signer/main.c
	$(CC) $(CFLAGS) -DALGO_MLDSA -c $< -o $@

signer/main_ed25519.o: signer/main.c
	$(CC) $(CFLAGS) -DALGO_ED25519 -c $< -o $@

signer/backend_mldsa.o: signer/backend_mldsa.c
	$(CC) $(CFLAGS) -DALGO_MLDSA -c $< -o $@

signer/backend_ed25519.o: signer/backend_ed25519.c
	$(CC) $(CFLAGS) -DALGO_ED25519 -c $< -o $@

signer/app-mldsa.elf: $(SIGNEROBJS_MLDSA)
	$(CC) $(CFLAGS) $(SIGNEROBJS_MLDSA) $(LDFLAGS) -L $(LIBDIR)/monocypher -lmonocypher -I $(LIBDIR) -o $@

signer/app-ed25519.elf: $(SIGNEROBJS_ED25519)
	$(CC) $(CFLAGS) $(SIGNEROBJS_ED25519) $(LDFLAGS) -L $(LIBDIR)/monocypher -lmonocypher -I $(LIBDIR) -o $@

signer/mldsa_native.o: $(MLDSADIR)/mldsa/mldsa_native.c
	$(CC) $(CFLAGS) -c $< -o $@

$(SIGNEROBJS_MLDSA) $(SIGNEROBJS_ED25519): $(INCLUDE)/tkey/tk1_mem.h signer/app_proto.h

.PHONY: clean
clean:
	rm -f signer/app-mldsa.bin signer/app-mldsa.elf $(SIGNEROBJS_MLDSA)
	rm -f signer/app-ed25519.bin signer/app-ed25519.elf $(SIGNEROBJS_ED25519)

# Uses ../.clang-format
FMTFILES=signer/*.[ch]

.PHONY: fmt
fmt:
	clang-format --dry-run --ferror-limit=0 $(FMTFILES)
	clang-format --verbose -i $(FMTFILES)
.PHONY: checkfmt
checkfmt:
	clang-format --dry-run --ferror-limit=0 --Werror $(FMTFILES)

.PHONY: podman
podman:
	podman run --arch=amd64 --rm --mount type=bind,source=$(CURDIR),target=/src --mount type=bind,source=$(LIBDIR),target=/tkey-libs -w /src -it $(IMAGE) make -j
