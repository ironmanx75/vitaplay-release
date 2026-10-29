/*
 * CarPlay pair-setup (SRP-6a with PIN 3939, then Ed25519 key exchange) and pair-verify
 * (X25519 + Ed25519) responders. Ports of PairSetup.kt and PairVerify.kt.
 */
#pragma once

#include "common.h"
#include "srp.h"

typedef struct {
    srp_session *srp;
    uint8_t session_key[64];
    bool have_key;
} pair_setup_state;

typedef struct {
    uint8_t own_pk[32], own_sk[32];
    uint8_t client_pk[32];
    uint8_t shared[32];
    uint8_t encryption_key[32];
    bool have_m2;
    bool verified;
    uint8_t control_read_key[32];
    uint8_t control_write_key[32];
    char controller_id[64];
} pair_verify_state;

void pair_setup_handle(pair_setup_state *s, const uint8_t *body, size_t len, buf_t *out);
void pair_setup_free(pair_setup_state *s);
void pair_verify_handle(pair_verify_state *s, const uint8_t *body, size_t len, buf_t *out);
