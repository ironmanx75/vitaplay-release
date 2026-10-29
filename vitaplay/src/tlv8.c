#include "tlv8.h"

#include <string.h>

#define MAX_FRAGMENT 255

void tlv8_decode(tlv8_t *out, const uint8_t *data, size_t len) {
    memset(out, 0, sizeof(*out));
    size_t pos = 0;
    int last_type = -1;
    size_t last_len = 0;
    while (pos + 2 <= len) {
        int type = data[pos];
        size_t item_len = data[pos + 1];
        pos += 2;
        if (pos + item_len > len) break;
        /* A full 255-byte fragment followed by the same type continues the value. */
        if (!(type == last_type && last_len == MAX_FRAGMENT)) buf_clear(&out->value[type]);
        buf_append(&out->value[type], data + pos, item_len);
        out->present[type] = true;
        pos += item_len;
        last_type = type;
        last_len = item_len;
    }
}

void tlv8_free(tlv8_t *t) {
    for (int i = 0; i < 256; i++) buf_free(&t->value[i]);
}

const buf_t *tlv8_get(const tlv8_t *t, int type) {
    return t->present[type] ? &t->value[type] : NULL;
}

void tlv8_put(buf_t *out, int type, const void *value, size_t len) {
    const uint8_t *p = value;
    size_t offset = 0;
    do {
        size_t chunk = len - offset > MAX_FRAGMENT ? MAX_FRAGMENT : len - offset;
        uint8_t header[2] = {(uint8_t)type, (uint8_t)chunk};
        buf_append(out, header, 2);
        buf_append(out, p + offset, chunk);
        offset += chunk;
    } while (offset < len);
}

void tlv8_put_byte(buf_t *out, int type, uint8_t value) { tlv8_put(out, type, &value, 1); }
