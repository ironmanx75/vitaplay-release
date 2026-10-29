#include "cipher.h"

#include <string.h>

#include "crypto.h"

#define MAX_PAYLOAD 0x4000

void cipher_init(ctrl_cipher *c, const uint8_t read_key[32], const uint8_t write_key[32]) {
    memcpy(c->read_key, read_key, 32);
    memcpy(c->write_key, write_key, 32);
    c->read_counter = 0;
    c->write_counter = 0;
}

int cipher_decrypt(ctrl_cipher *c, buf_t *in, buf_t *out) {
    size_t offset = 0;
    while (in->len - offset >= 2) {
        size_t length = in->data[offset] | (in->data[offset + 1] << 8);
        size_t frame_end = offset + 2 + length + AEAD_TAG;
        if (in->len < frame_end) break;
        uint8_t nonce[12];
        nonce64(nonce, c->read_counter);
        buf_reserve(out, length);
        if (chacha_open(out->data + out->len, c->read_key, nonce, in->data + offset + 2,
                        length + AEAD_TAG, in->data + offset, 2) != 0) {
            return -1;
        }
        out->len += length;
        c->read_counter++;
        offset = frame_end;
    }
    buf_consume(in, offset);
    return 0;
}

void cipher_encrypt(ctrl_cipher *c, const uint8_t *data, size_t len, buf_t *out) {
    size_t offset = 0;
    do {
        size_t chunk = len - offset > MAX_PAYLOAD ? MAX_PAYLOAD : len - offset;
        uint8_t header[2] = {(uint8_t)chunk, (uint8_t)(chunk >> 8)};
        uint8_t nonce[12];
        nonce64(nonce, c->write_counter++);
        buf_append(out, header, 2);
        buf_reserve(out, chunk + AEAD_TAG);
        chacha_seal(out->data + out->len, c->write_key, nonce, data + offset, chunk, header, 2);
        out->len += chunk + AEAD_TAG;
        offset += chunk;
    } while (offset < len);
}
