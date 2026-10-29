# VitaPlayBt kernel plugin: opens the RFCOMM iAP2 channel to the iPhone and exposes its bytes to
# userspace through the VitaPlayBt syscalls (vpbt_status / vpbt_read / vpbt_write). Built with the
# VitaSDK toolchain. Produces vitaplaybt.skprx plus a userspace stub (stubs/) for the app to link.
VITASDK ?= $(HOME)/vitasdk
PREFIX  := $(VITASDK)/bin/arm-vita-eabi
CC      := $(PREFIX)-gcc

CFLAGS  := -std=gnu11 -O2 -Wall -Wextra -Wno-unused-parameter -nostdlib -fno-builtin
LIBS    := -lSceBtForDriver_stub -lSceIofilemgrForDriver_stub -lSceSysclibForDriver_stub \
	-lSceThreadmgrForDriver_stub -lSceSysmemForDriver_stub -ltaihenForKernel_stub \
	-lSceModulemgrForKernel_363_stub # 3.63+ NIDs (target Vita is on 3.65)

STUBDIR := stubs
# vita-libs-gen names the archive after the MODULE (vitaplaybt), not the library (VitaPlayBt).
USERSTUB := $(STUBDIR)/libvitaplaybt_stub.a

all: vitaplaybt.skprx $(USERSTUB)

build:
	mkdir -p build

build/vitaplaybt.elf: vitaplaybt.c | build
	$(CC) $(CFLAGS) -Wl,-q $< $(LIBS) -o $@

build/vitaplaybt.velf: build/vitaplaybt.elf exports.yml
	$(VITASDK)/bin/vita-elf-create -e exports.yml $< $@

# Kernel modules are not "safe" homebrew, so no -s.
vitaplaybt.skprx: build/vitaplaybt.velf
	$(VITASDK)/bin/vita-make-fself -c $< $@

# Userspace stub for the VitaPlayBt syscall library. vita-elf-export reads the built ELF +
# exports.yml and writes an import db; vita-libs-gen turns that into a stub archive.
$(USERSTUB): build/vitaplaybt.elf exports.yml
	$(VITASDK)/bin/vita-elf-export k build/vitaplaybt.elf exports.yml build/imports.yml
	rm -rf $(STUBDIR)
	$(VITASDK)/bin/vita-libs-gen build/imports.yml $(STUBDIR)
	$(MAKE) -C $(STUBDIR)

clean:
	rm -rf build vitaplaybt.skprx $(STUBDIR)

.PHONY: all clean
