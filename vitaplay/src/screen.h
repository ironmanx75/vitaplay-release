/*
 * CarPlay main-screen stream receiver (port of ScreenStream.kt).
 *
 * Each message is a 128-byte header (u32le body size at 0, opcode at 4) and a body: a clear
 * VideoConfig (avcC) or a ChaCha20-Poly1305 sealed VideoFrame keyed by the DataStream output key,
 * nonce = per-frame counter, AAD = the header.
 */
#pragma once

#include "common.h"

typedef struct {
    void (*request_keyframe)(void *ctx);
    void (*closed)(void *ctx);
    void *ctx;
} screen_callbacks;

/* Opens SCREEN_PORT and starts the receive thread. Returns the port or -1. */
int screen_start(const uint8_t key[32], screen_callbacks callbacks);
void screen_stop(void);
bool screen_active(void);
