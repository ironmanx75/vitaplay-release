#include "bplist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- tree ---- */

static pl_node *pl_new(pl_type type) {
    pl_node *node = calloc(1, sizeof(*node));
    if (!node) abort();
    node->type = type;
    return node;
}

pl_node *pl_bool(bool value) {
    pl_node *n = pl_new(PL_BOOL);
    n->v.b = value;
    return n;
}

pl_node *pl_int(int64_t value) {
    pl_node *n = pl_new(PL_INT);
    n->v.i = value;
    return n;
}

pl_node *pl_uint(uint64_t value) {
    if (value <= (uint64_t)INT64_MAX) return pl_int((int64_t)value);
    pl_node *n = pl_new(PL_UINT);
    n->v.u = value;
    return n;
}

pl_node *pl_real(double value) {
    pl_node *n = pl_new(PL_REAL);
    n->v.r = value;
    return n;
}

static pl_node *pl_str_len(const char *value, size_t len) {
    pl_node *n = pl_new(PL_STRING);
    n->str = malloc(len + 1);
    memcpy(n->str, value, len);
    n->str[len] = 0;
    n->len = len;
    return n;
}

pl_node *pl_str(const char *value) { return pl_str_len(value, strlen(value)); }

pl_node *pl_data(const void *data, size_t len) {
    pl_node *n = pl_new(PL_DATA);
    n->data = malloc(len ? len : 1);
    if (len) memcpy(n->data, data, len);
    n->len = len;
    return n;
}

pl_node *pl_array(void) { return pl_new(PL_ARRAY); }
pl_node *pl_dict(void) { return pl_new(PL_DICT); }

static void pl_grow(pl_node *c) {
    if (c->count < c->cap) return;
    c->cap = c->cap ? c->cap * 2 : 8;
    c->items = realloc(c->items, c->cap * sizeof(*c->items));
    if (c->type == PL_DICT) c->keys = realloc(c->keys, c->cap * sizeof(*c->keys));
}

pl_node *pl_push(pl_node *array, pl_node *value) {
    pl_grow(array);
    array->items[array->count++] = value;
    return array;
}

pl_node *pl_set(pl_node *dict, const char *key, pl_node *value) {
    pl_grow(dict);
    dict->keys[dict->count] = strdup(key);
    dict->items[dict->count++] = value;
    return dict;
}

void pl_free(pl_node *node) {
    if (!node) return;
    for (size_t i = 0; i < node->count; i++) {
        pl_free(node->items[i]);
        if (node->keys) free(node->keys[i]);
    }
    free(node->items);
    free(node->keys);
    free(node->str);
    free(node->data);
    free(node);
}

const pl_node *pl_get(const pl_node *dict, const char *key) {
    if (!dict || dict->type != PL_DICT) return NULL;
    for (size_t i = 0; i < dict->count; i++) {
        if (strcmp(dict->keys[i], key) == 0) return dict->items[i];
    }
    return NULL;
}

const char *pl_get_str(const pl_node *dict, const char *key) {
    const pl_node *n = pl_get(dict, key);
    return n && n->type == PL_STRING ? n->str : "";
}

bool pl_get_int(const pl_node *dict, const char *key, int64_t *out) {
    const pl_node *n = pl_get(dict, key);
    if (!n) return false;
    if (n->type == PL_INT) *out = n->v.i;
    else if (n->type == PL_UINT) *out = (int64_t)n->v.u;
    else if (n->type == PL_REAL) *out = (int64_t)n->v.r;
    else if (n->type == PL_BOOL) *out = n->v.b;
    else return false;
    return true;
}

bool pl_get_u64(const pl_node *dict, const char *key, uint64_t *out) {
    const pl_node *n = pl_get(dict, key);
    if (!n) return false;
    if (n->type == PL_INT) *out = (uint64_t)n->v.i;
    else if (n->type == PL_UINT) *out = n->v.u;
    else return false;
    return true;
}

bool pl_truthy(const pl_node *node) {
    if (!node) return false;
    if (node->type == PL_BOOL) return node->v.b;
    if (node->type == PL_INT) return node->v.i != 0;
    return false;
}

/* ---- encoder ---- */

typedef struct {
    const pl_node *node;
    const char *key; /* set for dictionary key string objects */
    uint32_t *refs;
} enc_obj;

typedef struct {
    enc_obj *objs;
    size_t count;
    size_t cap;
} enc_ctx;

static uint32_t enc_add(enc_ctx *c, const pl_node *node, const char *key) {
    if (c->count == c->cap) {
        c->cap = c->cap ? c->cap * 2 : 32;
        c->objs = realloc(c->objs, c->cap * sizeof(*c->objs));
    }
    c->objs[c->count] = (enc_obj){node, key, NULL};
    return (uint32_t)c->count++;
}

static uint32_t enc_flatten(enc_ctx *c, const pl_node *node) {
    uint32_t index = enc_add(c, node, NULL);
    uint32_t *refs = NULL;
    if (node->type == PL_ARRAY) {
        refs = malloc((node->count + 1) * sizeof(*refs));
        for (size_t i = 0; i < node->count; i++) refs[i] = enc_flatten(c, node->items[i]);
    } else if (node->type == PL_DICT) {
        refs = malloc((node->count * 2 + 1) * sizeof(*refs));
        for (size_t i = 0; i < node->count; i++) refs[i] = enc_add(c, NULL, node->keys[i]);
        for (size_t i = 0; i < node->count; i++) refs[node->count + i] = enc_flatten(c, node->items[i]);
    }
    c->objs[index].refs = refs;
    return index;
}

static void put_be(buf_t *out, uint64_t value, int bytes) {
    uint8_t tmp[8];
    for (int i = 0; i < bytes; i++) tmp[i] = (uint8_t)(value >> (8 * (bytes - 1 - i)));
    buf_append(out, tmp, bytes);
}

static void enc_int(buf_t *out, int64_t value) {
    if (value >= 0 && value <= 0xff) {
        uint8_t m = 0x10;
        buf_append(out, &m, 1);
        put_be(out, (uint64_t)value, 1);
    } else if (value >= 0 && value <= 0xffff) {
        uint8_t m = 0x11;
        buf_append(out, &m, 1);
        put_be(out, (uint64_t)value, 2);
    } else if (value >= 0 && value <= 0xffffffffLL) {
        uint8_t m = 0x12;
        buf_append(out, &m, 1);
        put_be(out, (uint64_t)value, 4);
    } else {
        uint8_t m = 0x13;
        buf_append(out, &m, 1);
        put_be(out, (uint64_t)value, 8);
    }
}

static void enc_marker(buf_t *out, uint8_t high, size_t len) {
    if (len < 15) {
        uint8_t m = (uint8_t)(high | len);
        buf_append(out, &m, 1);
    } else {
        uint8_t m = (uint8_t)(high | 0x0f);
        buf_append(out, &m, 1);
        enc_int(out, (int64_t)len);
    }
}

static bool is_ascii(const char *s, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if ((uint8_t)s[i] >= 0x80) return false;
    }
    return true;
}

/* UTF-8 to UTF-16BE; invalid bytes become U+FFFD. */
static void utf8_to_utf16be(const char *s, size_t len, buf_t *out, size_t *units) {
    *units = 0;
    for (size_t i = 0; i < len;) {
        uint32_t cp = 0xfffd;
        uint8_t c = (uint8_t)s[i];
        size_t extra = c < 0x80 ? 0 : (c >> 5) == 6 ? 1 : (c >> 4) == 14 ? 2 : (c >> 3) == 30 ? 3 : 0;
        if (c < 0x80) cp = c;
        else if (extra && i + extra < len) {
            cp = c & (0x3f >> extra);
            for (size_t k = 1; k <= extra; k++) cp = (cp << 6) | ((uint8_t)s[i + k] & 0x3f);
        }
        i += extra + 1;
        if (cp >= 0x10000) {
            cp -= 0x10000;
            put_be(out, 0xd800 | (cp >> 10), 2);
            put_be(out, 0xdc00 | (cp & 0x3ff), 2);
            *units += 2;
        } else {
            put_be(out, cp, 2);
            *units += 1;
        }
    }
}

static void enc_string(buf_t *out, const char *s, size_t len) {
    if (is_ascii(s, len)) {
        enc_marker(out, 0x50, len);
        buf_append(out, s, len);
        return;
    }
    buf_t utf16 = {0};
    size_t units;
    utf8_to_utf16be(s, len, &utf16, &units);
    enc_marker(out, 0x60, units);
    buf_append(out, utf16.data, utf16.len);
    buf_free(&utf16);
}

static void enc_object(buf_t *out, const enc_obj *obj, int ref_size) {
    if (obj->key) {
        enc_string(out, obj->key, strlen(obj->key));
        return;
    }
    const pl_node *n = obj->node;
    uint8_t m;
    switch (n->type) {
    case PL_BOOL:
        m = n->v.b ? 0x09 : 0x08;
        buf_append(out, &m, 1);
        break;
    case PL_INT:
        enc_int(out, n->v.i);
        break;
    case PL_UINT:
        m = 0x14;
        buf_append(out, &m, 1);
        put_be(out, 0, 8);
        put_be(out, n->v.u, 8);
        break;
    case PL_REAL: {
        m = 0x23;
        buf_append(out, &m, 1);
        uint64_t bits;
        memcpy(&bits, &n->v.r, 8);
        put_be(out, bits, 8);
        break;
    }
    case PL_STRING:
        enc_string(out, n->str, n->len);
        break;
    case PL_DATA:
        enc_marker(out, 0x40, n->len);
        buf_append(out, n->data, n->len);
        break;
    case PL_ARRAY:
        enc_marker(out, 0xa0, n->count);
        for (size_t i = 0; i < n->count; i++) put_be(out, obj->refs[i], ref_size);
        break;
    case PL_DICT:
        enc_marker(out, 0xd0, n->count);
        for (size_t i = 0; i < n->count * 2; i++) put_be(out, obj->refs[i], ref_size);
        break;
    }
}

static int bytes_for(uint64_t max) {
    if (max <= 0xff) return 1;
    if (max <= 0xffff) return 2;
    if (max <= 0xffffffffULL) return 4;
    return 8;
}

void bplist_encode(const pl_node *root, buf_t *out) {
    enc_ctx c = {0};
    enc_flatten(&c, root);
    int ref_size = bytes_for(c.count);

    size_t start = out->len;
    buf_append(out, "bplist00", 8);
    uint64_t *offsets = malloc(c.count * sizeof(*offsets));
    for (size_t i = 0; i < c.count; i++) {
        offsets[i] = out->len - start;
        enc_object(out, &c.objs[i], ref_size);
    }
    uint64_t table = out->len - start;
    int offset_size = bytes_for(table);
    for (size_t i = 0; i < c.count; i++) put_be(out, offsets[i], offset_size);

    uint8_t trailer[32] = {0};
    trailer[6] = (uint8_t)offset_size;
    trailer[7] = (uint8_t)ref_size;
    for (int i = 0; i < 8; i++) {
        trailer[8 + i] = (uint8_t)((uint64_t)c.count >> (56 - 8 * i));
        trailer[24 + i] = (uint8_t)(table >> (56 - 8 * i));
    }
    buf_append(out, trailer, sizeof(trailer));

    for (size_t i = 0; i < c.count; i++) free(c.objs[i].refs);
    free(c.objs);
    free(offsets);
}

/* ---- decoder ---- */

typedef struct {
    const uint8_t *data;
    size_t len;
    int offset_size;
    int ref_size;
    uint64_t count;
    uint64_t table;
} dec_ctx;

static uint64_t get_be(const uint8_t *p, int bytes) {
    uint64_t v = 0;
    for (int i = 0; i < bytes; i++) v = (v << 8) | p[i];
    return v;
}

static bool dec_length(const dec_ctx *d, size_t *pos, uint8_t low, uint64_t *len) {
    if (low != 0x0f) {
        *len = low;
        return true;
    }
    if (*pos >= d->len) return false;
    uint8_t m = d->data[*pos];
    if ((m >> 4) != 1) return false;
    int bytes = 1 << (m & 0x0f);
    if (bytes > 8 || *pos + 1 + bytes > d->len) return false;
    *len = get_be(d->data + *pos + 1, bytes);
    *pos += 1 + bytes;
    return true;
}

static pl_node *dec_object(const dec_ctx *d, uint64_t index, int depth);

static bool dec_ref(const dec_ctx *d, size_t pos, uint64_t *ref) {
    if (pos + d->ref_size > d->len) return false;
    *ref = get_be(d->data + pos, d->ref_size);
    return *ref < d->count;
}

static pl_node *dec_object(const dec_ctx *d, uint64_t index, int depth) {
    if (depth > 32 || index >= d->count) return NULL;
    size_t entry = d->table + index * d->offset_size;
    if (entry + d->offset_size > d->len) return NULL;
    size_t pos = get_be(d->data + entry, d->offset_size);
    if (pos >= d->len) return NULL;
    uint8_t marker = d->data[pos++];
    uint8_t high = marker >> 4, low = marker & 0x0f;
    uint64_t len;

    switch (high) {
    case 0x0:
        return pl_bool(marker == 0x09);
    case 0x1: {
        int bytes = 1 << low;
        if (bytes > 16 || pos + bytes > d->len) return NULL;
        if (bytes == 16) return pl_uint(get_be(d->data + pos + 8, 8));
        /* 1/2/4-byte integers are unsigned; 8-byte integers are two's complement. */
        return pl_int((int64_t)get_be(d->data + pos, bytes));
    }
    case 0x2:
    case 0x3: {
        int bytes = high == 0x3 ? 8 : 1 << low;
        if (pos + bytes > d->len) return NULL;
        if (bytes == 4) {
            uint32_t bits = (uint32_t)get_be(d->data + pos, 4);
            float f;
            memcpy(&f, &bits, 4);
            return pl_real(f);
        }
        if (bytes != 8) return NULL;
        uint64_t bits = get_be(d->data + pos, 8);
        double r;
        memcpy(&r, &bits, 8);
        return pl_real(r);
    }
    case 0x4:
        if (!dec_length(d, &pos, low, &len) || pos + len > d->len) return NULL;
        return pl_data(d->data + pos, len);
    case 0x5:
        if (!dec_length(d, &pos, low, &len) || pos + len > d->len) return NULL;
        return pl_str_len((const char *)d->data + pos, len);
    case 0x6: {
        if (!dec_length(d, &pos, low, &len) || pos + len * 2 > d->len) return NULL;
        buf_t utf8 = {0};
        for (uint64_t i = 0; i < len; i++) {
            uint32_t cp = get_u16be(d->data + pos + i * 2);
            if (cp >= 0xd800 && cp < 0xdc00 && i + 1 < len) {
                uint32_t lo = get_u16be(d->data + pos + (i + 1) * 2);
                cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                i++;
            }
            uint8_t enc[4];
            int n;
            if (cp < 0x80) { enc[0] = cp; n = 1; }
            else if (cp < 0x800) { enc[0] = 0xc0 | (cp >> 6); enc[1] = 0x80 | (cp & 0x3f); n = 2; }
            else if (cp < 0x10000) {
                enc[0] = 0xe0 | (cp >> 12); enc[1] = 0x80 | ((cp >> 6) & 0x3f);
                enc[2] = 0x80 | (cp & 0x3f); n = 3;
            } else {
                enc[0] = 0xf0 | (cp >> 18); enc[1] = 0x80 | ((cp >> 12) & 0x3f);
                enc[2] = 0x80 | ((cp >> 6) & 0x3f); enc[3] = 0x80 | (cp & 0x3f); n = 4;
            }
            buf_append(&utf8, enc, n);
        }
        pl_node *node = pl_str_len(utf8.data ? (const char *)utf8.data : "", utf8.len);
        buf_free(&utf8);
        return node;
    }
    case 0x8:
        if (pos + low + 1 > d->len) return NULL;
        return pl_int((int64_t)get_be(d->data + pos, low + 1));
    case 0xa: {
        if (!dec_length(d, &pos, low, &len) || len > d->count) return NULL;
        pl_node *array = pl_array();
        for (uint64_t i = 0; i < len; i++) {
            uint64_t ref;
            pl_node *child;
            if (!dec_ref(d, pos + i * d->ref_size, &ref) || !(child = dec_object(d, ref, depth + 1))) {
                pl_free(array);
                return NULL;
            }
            pl_push(array, child);
        }
        return array;
    }
    case 0xd: {
        if (!dec_length(d, &pos, low, &len) || len > d->count) return NULL;
        pl_node *dict = pl_dict();
        for (uint64_t i = 0; i < len; i++) {
            uint64_t key_ref, value_ref;
            pl_node *key = NULL, *value = NULL;
            if (!dec_ref(d, pos + i * d->ref_size, &key_ref) ||
                !dec_ref(d, pos + (len + i) * d->ref_size, &value_ref) ||
                !(key = dec_object(d, key_ref, depth + 1)) || key->type != PL_STRING ||
                !(value = dec_object(d, value_ref, depth + 1))) {
                pl_free(key);
                pl_free(value);
                pl_free(dict);
                return NULL;
            }
            pl_set(dict, key->str, value);
            pl_free(key);
        }
        return dict;
    }
    default:
        return NULL;
    }
}

pl_node *bplist_decode(const uint8_t *data, size_t len) {
    if (len < 8 + 32 || memcmp(data, "bplist00", 8) != 0) return NULL;
    const uint8_t *t = data + len - 32;
    dec_ctx d = {data, len, t[6], t[7], get_be(t + 8, 8), get_be(t + 24, 8)};
    uint64_t top = get_be(t + 16, 8);
    if (d.offset_size < 1 || d.offset_size > 8 || d.ref_size < 1 || d.ref_size > 8) return NULL;
    if (d.table >= len || d.count == 0 || d.table + d.count * d.offset_size > len - 32) return NULL;
    return dec_object(&d, top, 0);
}

/* ---- debug ---- */

static void describe(const pl_node *n, buf_t *out, int depth) {
    char tmp[64];
    if (!n) {
        buf_append_str(out, "null");
        return;
    }
    switch (n->type) {
    case PL_BOOL: buf_append_str(out, n->v.b ? "true" : "false"); break;
    case PL_INT: snprintf(tmp, sizeof(tmp), "%lld", (long long)n->v.i); buf_append_str(out, tmp); break;
    case PL_UINT: snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)n->v.u); buf_append_str(out, tmp); break;
    case PL_REAL: snprintf(tmp, sizeof(tmp), "%g", n->v.r); buf_append_str(out, tmp); break;
    case PL_STRING: buf_append_str(out, "\""); buf_append(out, n->str, n->len); buf_append_str(out, "\""); break;
    case PL_DATA: snprintf(tmp, sizeof(tmp), "<%u bytes>", (unsigned)n->len); buf_append_str(out, tmp); break;
    case PL_ARRAY:
        buf_append_str(out, "[");
        for (size_t i = 0; i < n->count && depth < 4; i++) {
            if (i) buf_append_str(out, ",");
            describe(n->items[i], out, depth + 1);
        }
        buf_append_str(out, "]");
        break;
    case PL_DICT:
        buf_append_str(out, "{");
        for (size_t i = 0; i < n->count && depth < 4; i++) {
            if (i) buf_append_str(out, ",");
            buf_append_str(out, n->keys[i]);
            buf_append_str(out, "=");
            describe(n->items[i], out, depth + 1);
        }
        buf_append_str(out, "}");
        break;
    }
}

void pl_describe(const pl_node *node, char *out, size_t max) {
    buf_t text = {0};
    describe(node, &text, 0);
    size_t n = text.len < max - 1 ? text.len : max - 1;
    if (n) memcpy(out, text.data, n);
    out[n] = 0;
    buf_free(&text);
}
