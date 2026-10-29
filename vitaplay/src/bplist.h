/* Binary property list ("bplist00") tree, encoder and decoder (port of BplistCodec.kt). */
#pragma once

#include "common.h"

typedef enum {
    PL_BOOL,
    PL_INT,   /* signed 64-bit */
    PL_UINT,  /* unsigned 64-bit above INT64_MAX, encoded as a 128-bit integer */
    PL_REAL,
    PL_STRING,
    PL_DATA,
    PL_ARRAY,
    PL_DICT,
} pl_type;

typedef struct pl_node {
    pl_type type;
    union {
        bool b;
        int64_t i;
        uint64_t u;
        double r;
    } v;
    char *str;           /* PL_STRING, UTF-8 */
    uint8_t *data;       /* PL_DATA */
    size_t len;          /* PL_STRING / PL_DATA byte length */
    struct pl_node **items;
    char **keys;         /* PL_DICT */
    size_t count;
    size_t cap;
} pl_node;

pl_node *pl_bool(bool value);
pl_node *pl_int(int64_t value);
pl_node *pl_uint(uint64_t value);
pl_node *pl_real(double value);
pl_node *pl_str(const char *value);
pl_node *pl_data(const void *data, size_t len);
pl_node *pl_array(void);
pl_node *pl_dict(void);
/* Takes ownership of value; returns the container for chaining. */
pl_node *pl_push(pl_node *array, pl_node *value);
pl_node *pl_set(pl_node *dict, const char *key, pl_node *value);
void pl_free(pl_node *node);

const pl_node *pl_get(const pl_node *dict, const char *key);
const char *pl_get_str(const pl_node *dict, const char *key); /* "" when absent */
bool pl_get_int(const pl_node *dict, const char *key, int64_t *out);
bool pl_get_u64(const pl_node *dict, const char *key, uint64_t *out);
bool pl_truthy(const pl_node *node);

void bplist_encode(const pl_node *root, buf_t *out);
pl_node *bplist_decode(const uint8_t *data, size_t len); /* NULL on malformed input */

/* Debug: compact one-line rendering. */
void pl_describe(const pl_node *node, char *out, size_t max);
