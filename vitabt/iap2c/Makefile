# iap2c: portable C port of the iAP2 link layer. For vitabt we build a Vita static library;
# `iap2_link.c` is plain C, so you can also just compile it straight into your app instead.
VITASDK ?= $(HOME)/vitasdk
PREFIX  := $(VITASDK)/bin/arm-vita-eabi
CC      := $(PREFIX)-gcc
AR      := $(PREFIX)-ar

CFLAGS := -O2 -std=gnu11 -Wall -Wextra -Wno-unused-parameter
SRC    := iap2_link.c
OBJ    := build/iap2_link.o

all: build/libiap2c.a

build:
	mkdir -p build

build/%.o: %.c $(wildcard *.h) | build
	$(CC) $(CFLAGS) -c $< -o $@

build/libiap2c.a: $(OBJ)
	$(AR) rcs $@ $(OBJ)

clean:
	rm -rf build

.PHONY: all clean
