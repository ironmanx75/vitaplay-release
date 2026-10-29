#include "crypto.h"

#include <stdarg.h>
#include <string.h>

#include <mbedtls/aes.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <sodium.h>

static const char *rng_name(void) { return "sceKernelGetRandomNumber"; }
static uint32_t rng_random(void) {
    uint32_t value;
    rand_bytes(&value, sizeof(value));
    return value;
}
static void rng_buf(void *out, size_t len) { rand_bytes(out, len); }

static randombytes_implementation vita_rng = {
    .implementation_name = rng_name,
    .random = rng_random,
    .stir = NULL,
    .uniform = NULL,
    .buf = rng_buf,
    .close = NULL,
};

int crypto_setup(void) {
    randombytes_set_implementation(&vita_rng);
    return sodium_init() < 0 ? -1 : 0;
}

void x25519_generate(uint8_t pk[32], uint8_t sk[32]) {
    rand_bytes(sk, 32);
    crypto_scalarmult_base(pk, sk);
}

int x25519_shared(uint8_t out[32], const uint8_t sk[32], const uint8_t peer[32]) {
    return crypto_scalarmult(out, sk, peer) == 0 ? 0 : -1;
}

void ed25519_public(uint8_t pk[32], const uint8_t seed[32]) {
    uint8_t sk[64];
    crypto_sign_seed_keypair(pk, sk, seed);
    sodium_memzero(sk, sizeof(sk));
}

void ed25519_sign(uint8_t sig[64], const uint8_t seed[32], const uint8_t *msg, size_t len) {
    uint8_t pk[32], sk[64];
    crypto_sign_seed_keypair(pk, sk, seed);
    crypto_sign_detached(sig, NULL, msg, len, sk);
    sodium_memzero(sk, sizeof(sk));
}

bool ed25519_verify(const uint8_t pk[32], const uint8_t *msg, size_t len, const uint8_t sig[64]) {
    return crypto_sign_verify_detached(sig, msg, len, pk) == 0;
}

void hkdf_sha512_raw(uint8_t *out, size_t out_len, const uint8_t *ikm, size_t ikm_len,
                     const uint8_t *salt, size_t salt_len, const uint8_t *info, size_t info_len) {
    uint8_t prk[64];
    crypto_auth_hmacsha512_state state;
    crypto_auth_hmacsha512_init(&state, salt, salt_len);
    crypto_auth_hmacsha512_update(&state, ikm, ikm_len);
    crypto_auth_hmacsha512_final(&state, prk);

    uint8_t block[64];
    size_t produced = 0;
    for (uint8_t counter = 1; produced < out_len; counter++) {
        crypto_auth_hmacsha512_init(&state, prk, sizeof(prk));
        if (counter > 1) crypto_auth_hmacsha512_update(&state, block, sizeof(block));
        crypto_auth_hmacsha512_update(&state, info, info_len);
        crypto_auth_hmacsha512_update(&state, &counter, 1);
        crypto_auth_hmacsha512_final(&state, block);
        size_t take = out_len - produced < 64 ? out_len - produced : 64;
        memcpy(out + produced, block, take);
        produced += take;
    }
    sodium_memzero(prk, sizeof(prk));
}

void hkdf_sha512(uint8_t *out, size_t out_len, const uint8_t *ikm, size_t ikm_len,
                 const char *salt, const char *info) {
    hkdf_sha512_raw(out, out_len, ikm, ikm_len, (const uint8_t *)salt, strlen(salt),
                    (const uint8_t *)info, strlen(info));
}

void sha512_parts(uint8_t out[64], ...) {
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);
    va_list args;
    va_start(args, out);
    for (const uint8_t *part; (part = va_arg(args, const uint8_t *)) != NULL;) {
        size_t len = va_arg(args, size_t);
        crypto_hash_sha512_update(&state, part, len);
    }
    va_end(args);
    crypto_hash_sha512_final(&state, out);
}

void sha1_parts(uint8_t out[20], ...) {
    mbedtls_sha1_context ctx;
    mbedtls_sha1_init(&ctx);
    mbedtls_sha1_starts(&ctx);
    va_list args;
    va_start(args, out);
    for (const uint8_t *part; (part = va_arg(args, const uint8_t *)) != NULL;) {
        size_t len = va_arg(args, size_t);
        mbedtls_sha1_update(&ctx, part, len);
    }
    va_end(args);
    mbedtls_sha1_finish(&ctx, out);
    mbedtls_sha1_free(&ctx);
}

void sha256_parts(uint8_t out[32], ...) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    va_list args;
    va_start(args, out);
    for (const uint8_t *part; (part = va_arg(args, const uint8_t *)) != NULL;) {
        size_t len = va_arg(args, size_t);
        mbedtls_sha256_update(&ctx, part, len);
    }
    va_end(args);
    mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);
}

void chacha_seal(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *in,
                 size_t len, const uint8_t *aad, size_t aad_len) {
    unsigned long long out_len;
    crypto_aead_chacha20poly1305_ietf_encrypt(out, &out_len, in, len, aad, aad_len, NULL, nonce, key);
}

int chacha_open(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *in,
                size_t len, const uint8_t *aad, size_t aad_len) {
    unsigned long long out_len;
    if (len < AEAD_TAG) return -1;
    return crypto_aead_chacha20poly1305_ietf_decrypt(out, &out_len, NULL, in, len, aad, aad_len,
                                                     nonce, key) == 0 ? 0 : -1;
}

void nonce64(uint8_t out[12], uint64_t counter) {
    memset(out, 0, 4);
    for (int i = 4; i < 12; i++) {
        out[i] = (uint8_t)counter;
        counter >>= 8;
    }
}

void nonce_label(uint8_t out[12], const char *label) {
    memset(out, 0, 12);
    size_t len = strlen(label);
    memcpy(out + 4, label, len > 8 ? 8 : len);
}

void aes128_ctr(uint8_t *data, size_t len, const uint8_t key[16], const uint8_t iv[16]) {
    mbedtls_aes_context ctx;
    uint8_t counter[16], stream[16];
    size_t offset = 0;
    memcpy(counter, iv, 16);
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);
    mbedtls_aes_crypt_ctr(&ctx, len, &offset, counter, stream, data, data);
    mbedtls_aes_free(&ctx);
}

int vp_mbedtls_rng(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    rand_bytes(out, len);
    return 0;
}
