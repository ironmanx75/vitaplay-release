# VitaPlay - builds VitaPlay.vpk with the VitaSDK toolchain (no CMake needed).
#   make            build the VPK
#   make assets     regenerate LiveArea images (needs Java)

TITLE_ID := VPLY00001
TARGET   := VitaPlay
VERSION  := 00.10

VITASDK  ?= $(HOME)/vitasdk
PREFIX   := $(VITASDK)/bin/arm-vita-eabi
CC       := $(PREFIX)-gcc

SRC  := $(wildcard src/*.c)
OBJ  := $(patsubst src/%.c,build/%.o,$(SRC))

# Kernel byte-pump plugin for the on-device Bluetooth iAP2 bootstrap (src/btboot.c drives it).
BTPLUGIN     := btplugin/vitaplaybt.skprx
# Weak stub: VitaPlay must load even when the plugin is not resident (it is loaded at boot via
# taiHEN config.txt, not by this app), so the vpbt_* imports degrade to safe no-ops.
BTPLUGIN_STUB := btplugin/stubs/libvitaplaybt_stub_weak.a

CFLAGS  := -O2 -g -std=gnu11 -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers \
	-Wno-format-truncation
LDFLAGS := -Wl,-q
LIBS := \
	-Lbtplugin/stubs -lvitaplaybt_stub_weak \
	-lvita2d -lfreetype -lpng -ljpeg -lz -lbz2 \
	-lmbedtls -lmbedx509 -lmbedcrypto -lsodium -lopus \
	-lSceDisplay_stub -lSceGxm_stub -lSceSysmodule_stub -lSceCtrl_stub -lSceTouch_stub \
	-lScePgf_stub -lSceCommonDialog_stub -lSceAppMgr_stub -lSceAppUtil_stub \
	-lSceNet_stub -lSceNetCtl_stub -lScePower_stub -lSceVideodec_stub -lSceRtc_stub \
	-lSceAudio_stub \
	-lpthread -lm -lc

ASSETS := sce_sys/icon0.png sce_sys/livearea/contents/bg.png \
	sce_sys/livearea/contents/startup.png sce_sys/livearea/contents/template.xml

all: $(TARGET).vpk

build/%.o: src/%.c $(wildcard src/*.h) | build
	$(CC) $(CFLAGS) -c $< -o $@

build:
	mkdir -p build

# Build the kernel plugin and its userspace stub (recursive make in btplugin/).
$(BTPLUGIN) $(BTPLUGIN_STUB):
	$(MAKE) -C btplugin

$(OBJ): | $(BTPLUGIN_STUB)

build/$(TARGET).elf: $(OBJ) $(BTPLUGIN_STUB)
	$(CC) $(LDFLAGS) $(OBJ) $(LIBS) -o $@

build/$(TARGET).velf: build/$(TARGET).elf
	$(VITASDK)/bin/vita-elf-create $< $@

build/eboot.bin: build/$(TARGET).velf
	$(VITASDK)/bin/vita-make-fself -s $< $@

build/param.sfo:
	$(VITASDK)/bin/vita-mksfoex -s TITLE_ID=$(TITLE_ID) -s APP_VER=$(VERSION) "$(TARGET)" $@

$(TARGET).vpk: build/eboot.bin build/param.sfo $(ASSETS) $(BTPLUGIN)
	$(VITASDK)/bin/vita-pack-vpk -s build/param.sfo -b build/eboot.bin \
		$(foreach f,$(ASSETS),-a $(f)=$(f)) \
		-a $(BTPLUGIN)=vitaplaybt.skprx $@

assets:
	java tools/GenAssets.java sce_sys

clean:
	rm -rf build $(TARGET).vpk
	$(MAKE) -C btplugin clean

.PHONY: all assets clean
