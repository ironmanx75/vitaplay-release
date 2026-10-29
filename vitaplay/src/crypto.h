/* Primitives for CarPlay pairing and the control channel (port of AirPlayCrypto.kt). */
#pragma once

#include "common.h"

#define AEAD_TAG 16

int crypto_setup(void);

void x25519_generate(uint8_t pk[32], uint8_t sk[32]);
/* Returns -1 when the shared secret is all zero. */
int x25519_shared(uint8_t out[32], const uint8_t sk[32], const uint8_t peer[32]);

/* Ed25519 with a 32-byte seed as the private key, like BouncyCastle's raw encoding. */
void ed25519_public(uint8_t pk[32], const uint8_t seed[32]);
void ed25519_sign(uint8_t sig[64], const uint8_t seed[32], const uint8_t *msg, size_t len);
bool ed25519_verify(const uint8_t pk[32], const uint8_t *msg, size_t len, const uint8_t sig[64]);

void hkdf_sha512(uint8_t *out, size_t out_len, const uint8_t *ikm, size_t ikm_len,
                 const char *salt, const char *info);
void hkdf_sha512_raw(uint8_t *out, size_t out_len, const uint8_t *ikm, size_t ikm_len,
                     const uint8_t *salt, size_t salt_len, const uint8_t *info, size_t info_len);

/* Each part is (pointer, length); terminate the list with NULL. */
void sha512_parts(uint8_t out[64], ...);
void sha1_parts(uint8_t out[20], ...);
void sha256_parts(uint8_t out[32], ...);

/* ChaCha20-Poly1305 IETF. Seal writes len + 16 bytes; open returns -1 on a bad tag. */
void chacha_seal(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *in,
                 size_t len, const uint8_t *aad, size_t aad_len);
int chacha_open(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *in,
                size_t len, const uint8_t *aad, size_t aad_len);

/* Four zero bytes then an eight-byte little-endian counter. */
void nonce64(uint8_t out[12], uint64_t counter);
/* Four zero bytes then an eight-byte ASCII label such as "PV-Msg02". */
void nonce_label(uint8_t out[12], const char *label);

void aes128_ctr(uint8_t *data, size_t len, const uint8_t key[16], const uint8_t iv[16]);

/* mbedTLS-compatible RNG callback. */
int vp_mbedtls_rng(void *ctx, unsigned char *out, size_t len);
