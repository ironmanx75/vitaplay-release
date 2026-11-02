# softap kernel plugin: brings the Vita Wi-Fi up as an access point (uAP) via SceWlanBt.
# host-command UAP_SYS_CONFIG (0x00b0), by driving SceWlanBt's command path.
VITASDK ?= $(HOME)/vitasdk
PREFIX  := $(VITASDK)/bin/arm-vita-eabi
CC      := $(PREFIX)-gcc

CFLAGS := -std=gnu11 -O2 -Wall -Wextra -Wno-unused-parameter -nostdlib -fno-builtin
LIBS   := -lSceIofilemgrForDriver_stub -lSceSysclibForDriver_stub -lSceThreadmgrForDriver_stub \
	-ltaihenForKernel_stub -lSceModulemgrForKernel_363_stub

all: softap.skprx

build:
	mkdir -p build

build/softap.elf: softap.c | build
	$(CC) $(CFLAGS) -Wl,-q $< $(LIBS) -o $@

build/softap.velf: build/softap.elf exports.yml
	$(VITASDK)/bin/vita-elf-create -e exports.yml $< $@

softap.skprx: build/softap.velf
	$(VITASDK)/bin/vita-make-fself -c $< $@

clean:
	rm -rf build softap.skprx

.PHONY: all clean
