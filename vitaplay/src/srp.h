/* SRP-6a server, RFC 5054 3072-bit group with SHA-512 (port of Srp6a.kt). */
#pragma once

#include "common.h"

#define SRP_N_BYTES 384

typedef struct srp_session srp_session;

srp_session *srp_start(const char *username, const char *password);
void srp_free(srp_session *s);
const uint8_t *srp_salt(const srp_session *s);           /* 16 bytes */
const uint8_t *srp_public_key(const srp_session *s);     /* SRP_N_BYTES, padded B */

/* Checks the client proof; on success fills the 64-byte session key and server proof. */
bool srp_verify(srp_session *s, const uint8_t *a, size_t a_len, const uint8_t *m1, size_t m1_len,
                uint8_t key_out[64], uint8_t proof_out[64]);
