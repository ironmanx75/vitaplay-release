/*
 * ChaCha20-Poly1305 framing for the control and event channels (port of ControlCipher.kt).
 * Frame: [u16le length][ciphertext][16-byte tag]; the length is the AAD and each direction keeps
 * its own 64-bit nonce counter.
 */
#pragma once

#include "common.h"

typedef struct {
    uint8_t read_key[32];
    uint8_t write_key[32];
    uint64_t read_counter;
    uint64_t write_counter;
} ctrl_cipher;

void cipher_init(ctrl_cipher *c, const uint8_t read_key[32], const uint8_t write_key[32]);
/* Decrypts every complete frame at the front of in into out. Returns -1 on a bad tag. */
int cipher_decrypt(ctrl_cipher *c, buf_t *in, buf_t *out);
void cipher_encrypt(ctrl_cipher *c, const uint8_t *data, size_t len, buf_t *out);
