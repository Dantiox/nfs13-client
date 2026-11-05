# Copyright (C) 2026 Dantiox and sn0wd0wn (gregel, Dantiox, Alexes)
# SPDX-License-Identifier: AGPL-3.0-only
CC = i686-w64-mingw32-gcc
CFLAGS = -Wall -Wextra -O2 -shared -m32
LDFLAGS = -s -static-libgcc -Wl,--enable-stdcall-fixup -lws2_32 -ladvapi32

TARGET = d3d11.dll
SRC = proxy_d3d11.c
DEF = d3d11.def

all: $(TARGET)

$(TARGET): $(SRC) $(DEF) hook_engine.h
	$(CC) $(CFLAGS) $(SRC) $(DEF) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
