/* HomeKit/AirPlay TLV8 codec for the pairing messages (port of Tlv8Codec.kt). */
#pragma once

#include "common.h"

enum {
    TLV_METHOD = 0x00,
    TLV_IDENTIFIER = 0x01,
    TLV_SALT = 0x02,
    TLV_PUBLIC_KEY = 0x03,
    TLV_PROOF = 0x04,
    TLV_ENCRYPTED_DATA = 0x05,
    TLV_STATE = 0x06,
    TLV_ERROR = 0x07,
    TLV_SIGNATURE = 0x0a,
};

typedef struct {
    buf_t value[256];
    bool present[256];
} tlv8_t;

void tlv8_decode(tlv8_t *out, const uint8_t *data, size_t len);
void tlv8_free(tlv8_t *t);
/* Returns the item or NULL when absent. */
const buf_t *tlv8_get(const tlv8_t *t, int type);

void tlv8_put(buf_t *out, int type, const void *value, size_t len);
void tlv8_put_byte(buf_t *out, int type, uint8_t value);
