#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mfi.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/ecdsa.h>
#include <mbedtls/pk.h>

#include "crypto.h"

#define MFI_DIR APP_DIR "/offline-mfi"
#define MAX_FILE_BYTES (16 * 1024)

static mbedtls_pk_context key;
static uint8_t *certificate;
static size_t certificate_len;
static bool ready;
static char status[96] = "MFi identity not loaded";
static pthread_mutex_t sign_lock = PTHREAD_MUTEX_INITIALIZER;

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    uint8_t *data = malloc(MAX_FILE_BYTES);
    *len = fread(data, 1, MAX_FILE_BYTES, f);
    fclose(f);
    if (*len == 0 || *len == MAX_FILE_BYTES) {
        free(data);
        return NULL;
    }
    return data;
}

int mfi_load(void) {
    size_t key_len;
    uint8_t *key_der = read_file(MFI_DIR "/identity.pk8", &key_len);
    certificate = read_file(MFI_DIR "/certificate.p7b", &certificate_len);
    if (!key_der || !certificate) {
        snprintf(status, sizeof(status), "Missing %s/identity.pk8 or certificate.p7b", MFI_DIR);
        free(key_der);
        return -1;
    }

    mbedtls_pk_init(&key);
    int rc = mbedtls_pk_parse_key(&key, key_der, key_len, NULL, 0, vp_mbedtls_rng, NULL);
    memset(key_der, 0, key_len);
    free(key_der);
    if (rc != 0 || mbedtls_pk_get_type(&key) != MBEDTLS_PK_ECKEY ||
        mbedtls_pk_ec(key)->grp.id != MBEDTLS_ECP_DP_SECP256R1) {
        snprintf(status, sizeof(status), "identity.pk8 is not a P-256 key (rc=-0x%04x)", -rc);
        return -1;
    }

    /* Self-test: sign a random digest and verify it with the same key. */
    uint8_t digest[32], sig[64];
    rand_bytes(digest, sizeof(digest));
    ready = true;
    if (mfi_sign_digest(digest, sig) != 0) {
        ready = false;
        snprintf(status, sizeof(status), "MFi signing self-test failed");
        return -1;
    }
    snprintf(status, sizeof(status), "MFi identity loaded (cert %u bytes)", (unsigned)certificate_len);
    vp_log("%s", status);
    return 0;
}

bool mfi_ready(void) { return ready; }
const char *mfi_status(void) { return status; }

const uint8_t *mfi_cert(size_t *len) {
    *len = ready ? certificate_len : 0;
    return ready ? certificate : NULL;
}

int mfi_sign_digest(const uint8_t digest[32], uint8_t sig[64]) {
    if (!ready) return -1;
    pthread_mutex_lock(&sign_lock);
    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(key);
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    int rc = mbedtls_ecdsa_sign(&ec->grp, &r, &s, &ec->d, digest, 32, vp_mbedtls_rng, NULL);
    if (rc == 0) rc = mbedtls_ecdsa_verify(&ec->grp, digest, 32, &ec->Q, &r, &s);
    if (rc == 0) {
        mbedtls_mpi_write_binary(&r, sig, 32);
        mbedtls_mpi_write_binary(&s, sig + 32, 32);
    }
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    pthread_mutex_unlock(&sign_lock);
    return rc == 0 ? 0 : -1;
}

int mfi_auth_setup(const uint8_t *body, size_t len, buf_t *out) {
    if (!ready || len != 33 || body[0] != 0x01) return -1;
    const uint8_t *peer = body + 1;

    uint8_t pk[32], sk[32], shared[32];
    x25519_generate(pk, sk);
    if (x25519_shared(shared, sk, peer) != 0) return -1;

    uint8_t aes_key[20], aes_iv[20];
    sha1_parts(aes_key, "AES-KEY", (size_t)7, shared, sizeof(shared), NULL);
    sha1_parts(aes_iv, "AES-IV", (size_t)6, shared, sizeof(shared), NULL);

    /* Software identities speak MFi protocol 3: SHA-256 over both public keys. */
    uint8_t digest[32], sig[64];
    sha256_parts(digest, pk, sizeof(pk), peer, (size_t)32, NULL);
    if (mfi_sign_digest(digest, sig) != 0) return -1;
    aes128_ctr(sig, sizeof(sig), aes_key, aes_iv);

    uint8_t len_be[4];
    buf_append(out, pk, 32);
    put_u32be(len_be, (uint32_t)certificate_len);
    buf_append(out, len_be, 4);
    buf_append(out, certificate, certificate_len);
    put_u32be(len_be, sizeof(sig));
    buf_append(out, len_be, 4);
    buf_append(out, sig, sizeof(sig));
    vp_log("auth-setup answered with MFi certificate");
    return 0;
}
