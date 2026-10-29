#include "srp.h"

#include <stdlib.h>
#include <string.h>

#include <mbedtls/bignum.h>

#include "crypto.h"

static const char N_HEX[] =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183"
    "995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A"
    "85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7AB"
    "F5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D8"
    "7602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208"
    "E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

struct srp_session {
    mbedtls_mpi n, g, v, b, big_b;
    uint8_t salt[16];
    uint8_t identifier[32];
    size_t identifier_len;
    uint8_t padded_b[SRP_N_BYTES];
};

/* Minimal big-endian encoding, as BigInteger.toByteArray() without the sign byte. */
static size_t mpi_minimal(const mbedtls_mpi *x, uint8_t *out, size_t max) {
    size_t len = mbedtls_mpi_size(x);
    if (len == 0) {
        out[0] = 0;
        return 1;
    }
    if (len > max) return 0;
    mbedtls_mpi_write_binary(x, out, len);
    return len;
}

static void mpi_padded(const mbedtls_mpi *x, uint8_t out[SRP_N_BYTES]) {
    mbedtls_mpi_write_binary(x, out, SRP_N_BYTES);
}

srp_session *srp_start(const char *username, const char *password) {
    srp_session *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    mbedtls_mpi_init(&s->n);
    mbedtls_mpi_init(&s->g);
    mbedtls_mpi_init(&s->v);
    mbedtls_mpi_init(&s->b);
    mbedtls_mpi_init(&s->big_b);
    mbedtls_mpi_read_string(&s->n, 16, N_HEX);
    mbedtls_mpi_lset(&s->g, 5);

    s->identifier_len = strlen(username);
    memcpy(s->identifier, username, s->identifier_len);
    rand_bytes(s->salt, sizeof(s->salt));

    /* x = H(salt | H(I ":" P)), v = g^x */
    uint8_t inner[64], xh[64];
    sha512_parts(inner, username, strlen(username), ":", (size_t)1, password, strlen(password), NULL);
    sha512_parts(xh, s->salt, sizeof(s->salt), inner, sizeof(inner), NULL);
    mbedtls_mpi x;
    mbedtls_mpi_init(&x);
    mbedtls_mpi_read_binary(&x, xh, sizeof(xh));
    mbedtls_mpi_exp_mod(&s->v, &s->g, &x, &s->n, NULL);
    mbedtls_mpi_free(&x);

    /* k = H(N | pad(g)) */
    uint8_t n_bytes[SRP_N_BYTES], g_pad[SRP_N_BYTES], kh[64];
    size_t n_len = mpi_minimal(&s->n, n_bytes, sizeof(n_bytes));
    mpi_padded(&s->g, g_pad);
    sha512_parts(kh, n_bytes, n_len, g_pad, sizeof(g_pad), NULL);

    uint8_t b_raw[32];
    rand_bytes(b_raw, sizeof(b_raw));
    mbedtls_mpi_read_binary(&s->b, b_raw, sizeof(b_raw));

    /* B = (k*v + g^b) mod N */
    mbedtls_mpi k, kv, gb;
    mbedtls_mpi_init(&k);
    mbedtls_mpi_init(&kv);
    mbedtls_mpi_init(&gb);
    mbedtls_mpi_read_binary(&k, kh, sizeof(kh));
    mbedtls_mpi_mul_mpi(&kv, &k, &s->v);
    mbedtls_mpi_exp_mod(&gb, &s->g, &s->b, &s->n, NULL);
    mbedtls_mpi_add_mpi(&kv, &kv, &gb);
    mbedtls_mpi_mod_mpi(&s->big_b, &kv, &s->n);
    mbedtls_mpi_free(&k);
    mbedtls_mpi_free(&kv);
    mbedtls_mpi_free(&gb);

    mpi_padded(&s->big_b, s->padded_b);
    return s;
}

void srp_free(srp_session *s) {
    if (!s) return;
    mbedtls_mpi_free(&s->n);
    mbedtls_mpi_free(&s->g);
    mbedtls_mpi_free(&s->v);
    mbedtls_mpi_free(&s->b);
    mbedtls_mpi_free(&s->big_b);
    free(s);
}

const uint8_t *srp_salt(const srp_session *s) { return s->salt; }
const uint8_t *srp_public_key(const srp_session *s) { return s->padded_b; }

bool srp_verify(srp_session *s, const uint8_t *a_bytes, size_t a_len, const uint8_t *m1,
                size_t m1_len, uint8_t key_out[64], uint8_t proof_out[64]) {
    bool ok = false;
    mbedtls_mpi a, u, t, sv;
    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&u);
    mbedtls_mpi_init(&t);
    mbedtls_mpi_init(&sv);
    uint8_t a_pad[SRP_N_BYTES], s_bytes[SRP_N_BYTES], n_bytes[SRP_N_BYTES];

    if (a_len > SRP_N_BYTES || m1_len != 64) goto done;
    mbedtls_mpi_read_binary(&a, a_bytes, a_len);
    mbedtls_mpi_mod_mpi(&t, &a, &s->n);
    if (mbedtls_mpi_cmp_int(&t, 0) == 0) goto done;
    mpi_padded(&a, a_pad);

    /* u = H(pad(A) | pad(B)), S = (A * v^u)^b mod N, K = H(S) */
    uint8_t uh[64];
    sha512_parts(uh, a_pad, sizeof(a_pad), s->padded_b, sizeof(s->padded_b), NULL);
    mbedtls_mpi_read_binary(&u, uh, sizeof(uh));
    mbedtls_mpi_exp_mod(&t, &s->v, &u, &s->n, NULL);
    mbedtls_mpi_mul_mpi(&t, &t, &a);
    mbedtls_mpi_mod_mpi(&t, &t, &s->n);
    mbedtls_mpi_exp_mod(&sv, &t, &s->b, &s->n, NULL);
    size_t s_len = mpi_minimal(&sv, s_bytes, sizeof(s_bytes));
    uint8_t key[64];
    sha512_parts(key, s_bytes, s_len, NULL);

    /* M1 = H(H(N) xor H(g) | H(I) | salt | pad(A) | pad(B) | K) */
    size_t n_len = mpi_minimal(&s->n, n_bytes, sizeof(n_bytes));
    uint8_t hn[64], hg[64], hi[64], expected[64];
    uint8_t g_byte = 5;
    sha512_parts(hn, n_bytes, n_len, NULL);
    sha512_parts(hg, &g_byte, (size_t)1, NULL);
    for (int i = 0; i < 64; i++) hn[i] ^= hg[i];
    sha512_parts(hi, s->identifier, s->identifier_len, NULL);
    sha512_parts(expected, hn, sizeof(hn), hi, sizeof(hi), s->salt, sizeof(s->salt), a_pad,
                 sizeof(a_pad), s->padded_b, sizeof(s->padded_b), key, sizeof(key), NULL);
    if (memcmp(expected, m1, 64) != 0) goto done;

    sha512_parts(proof_out, a_pad, sizeof(a_pad), m1, (size_t)64, key, sizeof(key), NULL);
    memcpy(key_out, key, 64);
    ok = true;

done:
    mbedtls_mpi_free(&a);
    mbedtls_mpi_free(&u);
    mbedtls_mpi_free(&t);
    mbedtls_mpi_free(&sv);
    return ok;
}
