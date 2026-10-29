/*
 * iAP2 control-session messages (port of Iap2CsmFramer, Iap2Wire, Iap2WireCodec and
 * Iap2BodyBuilder): `0x4040 | u16 length | u16 messageId | parameters`, each parameter
 * `u16 length | u16 id | payload`, all big-endian. Strings are UTF-8 with a NUL terminator; a
 * group is a nested parameter list.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define IAP2_CSM_HEADER 6
#define IAP2_CSM_MAX_FRAME 0xffff
#define IAP2_CSM_MAX_DEPTH 8

/* ---- building ---- */

typedef struct {
    uint8_t *buf;
    size_t len, cap;
    bool failed; /* allocation failure, oversize message, or unbalanced groups */
    size_t open_groups[IAP2_CSM_MAX_DEPTH];
    int depth;
} iap2_builder;

void iap2_b_init(iap2_builder *b, uint16_t message_id);
void iap2_b_void(iap2_builder *b, uint16_t id);
void iap2_b_u8(iap2_builder *b, uint16_t id, uint8_t value);
void iap2_b_bool(iap2_builder *b, uint16_t id, bool value);
void iap2_b_u16(iap2_builder *b, uint16_t id, uint16_t value);
void iap2_b_u32(iap2_builder *b, uint16_t id, uint32_t value);
void iap2_b_u64(iap2_builder *b, uint16_t id, uint64_t value);
void iap2_b_bytes(iap2_builder *b, uint16_t id, const void *data, size_t len);
void iap2_b_string(iap2_builder *b, uint16_t id, const char *value);
void iap2_b_strings(iap2_builder *b, uint16_t id, const char *const *values, size_t count);
void iap2_b_u16_list(iap2_builder *b, uint16_t id, const uint16_t *values, size_t count);
void iap2_b_group_begin(iap2_builder *b, uint16_t id);
void iap2_b_group_end(iap2_builder *b);
/* Completes the frame. On success returns 0 and hands over the buffer (free() it); else -1. */
int iap2_b_finish(iap2_builder *b, uint8_t **frame, size_t *len);
void iap2_b_free(iap2_builder *b);

/* ---- reading ---- */

typedef struct {
    uint16_t id;
    const uint8_t *data;
    size_t len;
} iap2_param;

/* 0 if body is a well-formed parameter list (groups are not descended into), else -1. */
int iap2_params_check(const uint8_t *body, size_t len);
/* Iterates a parameter list: start with *offset = 0. Returns false at the end or on malformed input. */
bool iap2_params_next(const uint8_t *body, size_t len, size_t *offset, iap2_param *out);
/* The first parameter with this id. */
bool iap2_params_find(const uint8_t *body, size_t len, uint16_t id, iap2_param *out);

/* Typed views of a parameter's payload; false if the payload has the wrong size. */
bool iap2_param_u8(const iap2_param *p, uint8_t *out);
bool iap2_param_u16(const iap2_param *p, uint16_t *out);
bool iap2_param_u32(const iap2_param *p, uint32_t *out);
bool iap2_param_u64(const iap2_param *p, uint64_t *out);
/* A NUL-terminated string payload; returns the string inside the payload, or NULL. */
const char *iap2_param_string(const iap2_param *p);

/* ---- reassembly ---- */

/* Collects complete control-session messages from link payload chunks. */
typedef struct {
    uint8_t buf[IAP2_CSM_MAX_FRAME];
    size_t len;
} iap2_csm_framer;

typedef void (*iap2_csm_message_fn)(void *ctx, uint16_t message_id, const uint8_t *body, size_t body_len);

void iap2_csm_framer_init(iap2_csm_framer *f);
/* Adds bytes and calls on_message for every complete message (skipping garbage before 0x4040). */
void iap2_csm_feed(iap2_csm_framer *f, const uint8_t *data, size_t len, iap2_csm_message_fn on_message, void *ctx);
