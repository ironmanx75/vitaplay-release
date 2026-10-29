#include "pairing.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "identity.h"
#include "tlv8.h"

#define ERROR_AUTHENTICATION 2

static void put_error(buf_t *out, int state) {
    buf_clear(out);
    tlv8_put_byte(out, TLV_STATE, (uint8_t)state);
    tlv8_put_byte(out, TLV_ERROR, ERROR_AUTHENTICATION);
}

static int tlv_state(const tlv8_t *t) {
    const buf_t *state = tlv8_get(t, TLV_STATE);
    return state && state->len ? state->data[0] : 0;
}

/* ---- pair-setup ---- */

static void setup_m2(pair_setup_state *s, buf_t *out) {
    srp_free(s->srp);
    s->have_key = false;
    vp_log("pair-setup M1: computing SRP verifier");
    s->srp = srp_start("Pair-Setup", "3939");
    if (!s->srp) {
        put_error(out, 2);
        return;
    }
    tlv8_put_byte(out, TLV_STATE, 2);
    tlv8_put(out, TLV_PUBLIC_KEY, srp_public_key(s->srp), SRP_N_BYTES);
    tlv8_put(out, TLV_SALT, srp_salt(s->srp), 16);
}

static void setup_m4(pair_setup_state *s, const tlv8_t *t, buf_t *out) {
    const buf_t *a = tlv8_get(t, TLV_PUBLIC_KEY), *proof = tlv8_get(t, TLV_PROOF);
    uint8_t server_proof[64];
    if (!s->srp || !a || !proof ||
        !srp_verify(s->srp, a->data, a->len, proof->data, proof->len, s->session_key, server_proof)) {
        vp_log("pair-setup M3: SRP proof rejected");
        put_error(out, 4);
        return;
    }
    s->have_key = true;
    tlv8_put_byte(out, TLV_STATE, 4);
    tlv8_put(out, TLV_PROOF, server_proof, sizeof(server_proof));
}

static void setup_m6(pair_setup_state *s, const tlv8_t *t, buf_t *out) {
    const buf_t *encrypted = tlv8_get(t, TLV_ENCRYPTED_DATA);
    if (!s->have_key || !encrypted || encrypted->len < 16) {
        put_error(out, 6);
        return;
    }
    uint8_t key[32], nonce[12];
    hkdf_sha512(key, 32, s->session_key, 64, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info");
    nonce_label(nonce, "PS-Msg05");
    uint8_t *plain = malloc(encrypted->len);
    if (chacha_open(plain, key, nonce, encrypted->data, encrypted->len, NULL, 0) != 0) {
        free(plain);
        put_error(out, 6);
        return;
    }
    tlv8_t sub;
    tlv8_decode(&sub, plain, encrypted->len - 16);
    free(plain);

    const buf_t *id = tlv8_get(&sub, TLV_IDENTIFIER), *ltpk = tlv8_get(&sub, TLV_PUBLIC_KEY),
                *sig = tlv8_get(&sub, TLV_SIGNATURE);
    if (!id || !ltpk || !sig || ltpk->len != 32 || sig->len != 64 || id->len >= 64) {
        tlv8_free(&sub);
        put_error(out, 6);
        return;
    }

    uint8_t controller_sign_key[32];
    hkdf_sha512(controller_sign_key, 32, s->session_key, 64, "Pair-Setup-Controller-Sign-Salt",
                "Pair-Setup-Controller-Sign-Info");
    buf_t signed_data = {0};
    buf_append(&signed_data, controller_sign_key, 32);
    buf_append(&signed_data, id->data, id->len);
    buf_append(&signed_data, ltpk->data, 32);
    bool valid = ed25519_verify(ltpk->data, signed_data.data, signed_data.len, sig->data);
    buf_free(&signed_data);
    if (!valid) {
        tlv8_free(&sub);
        vp_log("pair-setup M5: controller signature invalid");
        put_error(out, 6);
        return;
    }
    char controller_id[64];
    memcpy(controller_id, id->data, id->len);
    controller_id[id->len] = 0;
    pairings_save(controller_id, ltpk->data);
    tlv8_free(&sub);

    uint8_t accessory_sign_key[32], signature[64];
    hkdf_sha512(accessory_sign_key, 32, s->session_key, 64, "Pair-Setup-Accessory-Sign-Salt",
                "Pair-Setup-Accessory-Sign-Info");
    const char *accessory_id = g_identity.pairing_id;
    buf_t accessory_data = {0};
    buf_append(&accessory_data, accessory_sign_key, 32);
    buf_append_str(&accessory_data, accessory_id);
    buf_append(&accessory_data, g_identity.public_key, 32);
    ed25519_sign(signature, g_identity.seed, accessory_data.data, accessory_data.len);
    buf_free(&accessory_data);

    buf_t response_sub = {0};
    tlv8_put(&response_sub, TLV_IDENTIFIER, accessory_id, strlen(accessory_id));
    tlv8_put(&response_sub, TLV_PUBLIC_KEY, g_identity.public_key, 32);
    tlv8_put(&response_sub, TLV_SIGNATURE, signature, 64);
    uint8_t *sealed = malloc(response_sub.len + 16);
    nonce_label(nonce, "PS-Msg06");
    chacha_seal(sealed, key, nonce, response_sub.data, response_sub.len, NULL, 0);

    tlv8_put_byte(out, TLV_STATE, 6);
    tlv8_put(out, TLV_ENCRYPTED_DATA, sealed, response_sub.len + 16);
    free(sealed);
    buf_free(&response_sub);
    vp_log("pair-setup complete with controller %s", controller_id);
}

void pair_setup_handle(pair_setup_state *s, const uint8_t *body, size_t len, buf_t *out) {
    tlv8_t t;
    tlv8_decode(&t, body, len);
    int state = tlv_state(&t);
    switch (state) {
    case 1: setup_m2(s, out); break;
    case 3: setup_m4(s, &t, out); break;
    case 5: setup_m6(s, &t, out); break;
    default: put_error(out, state); break;
    }
    tlv8_free(&t);
}

void pair_setup_free(pair_setup_state *s) {
    srp_free(s->srp);
    s->srp = NULL;
}

/* ---- pair-verify ---- */

static void verify_m2(pair_verify_state *s, const tlv8_t *t, buf_t *out) {
    const buf_t *client = tlv8_get(t, TLV_PUBLIC_KEY);
    if (!client || client->len != 32) {
        put_error(out, 2);
        return;
    }
    memcpy(s->client_pk, client->data, 32);
    x25519_generate(s->own_pk, s->own_sk);
    if (x25519_shared(s->shared, s->own_sk, s->client_pk) != 0) {
        put_error(out, 2);
        return;
    }
    hkdf_sha512(s->encryption_key, 32, s->shared, 32, "Pair-Verify-Encrypt-Salt",
                "Pair-Verify-Encrypt-Info");

    const char *accessory_id = g_identity.pairing_id;
    buf_t sign_data = {0};
    buf_append(&sign_data, s->own_pk, 32);
    buf_append_str(&sign_data, accessory_id);
    buf_append(&sign_data, s->client_pk, 32);
    uint8_t signature[64];
    ed25519_sign(signature, g_identity.seed, sign_data.data, sign_data.len);
    buf_free(&sign_data);

    buf_t sub = {0};
    tlv8_put(&sub, TLV_IDENTIFIER, accessory_id, strlen(accessory_id));
    tlv8_put(&sub, TLV_SIGNATURE, signature, 64);
    uint8_t nonce[12];
    nonce_label(nonce, "PV-Msg02");
    uint8_t *sealed = malloc(sub.len + 16);
    chacha_seal(sealed, s->encryption_key, nonce, sub.data, sub.len, NULL, 0);

    tlv8_put_byte(out, TLV_STATE, 2);
    tlv8_put(out, TLV_PUBLIC_KEY, s->own_pk, 32);
    tlv8_put(out, TLV_ENCRYPTED_DATA, sealed, sub.len + 16);
    free(sealed);
    buf_free(&sub);
    s->have_m2 = true;
    s->verified = false;
}

static void verify_m4(pair_verify_state *s, const tlv8_t *t, buf_t *out) {
    const buf_t *encrypted = tlv8_get(t, TLV_ENCRYPTED_DATA);
    if (!s->have_m2 || !encrypted || encrypted->len < 16) {
        put_error(out, 4);
        return;
    }
    uint8_t nonce[12];
    nonce_label(nonce, "PV-Msg03");
    uint8_t *plain = malloc(encrypted->len);
    if (chacha_open(plain, s->encryption_key, nonce, encrypted->data, encrypted->len, NULL, 0) != 0) {
        free(plain);
        put_error(out, 4);
        return;
    }
    tlv8_t sub;
    tlv8_decode(&sub, plain, encrypted->len - 16);
    free(plain);
    const buf_t *id = tlv8_get(&sub, TLV_IDENTIFIER), *sig = tlv8_get(&sub, TLV_SIGNATURE);
    char controller_id[64] = {0};
    uint8_t ltpk[32];
    bool ok = id && sig && sig->len == 64 && id->len < sizeof(controller_id);
    if (ok) {
        memcpy(controller_id, id->data, id->len);
        ok = pairings_get(controller_id, ltpk);
        if (!ok) vp_log("pair-verify: unknown controller %s (pair again)", controller_id);
    }
    if (ok) {
        buf_t data = {0};
        buf_append(&data, s->client_pk, 32);
        buf_append(&data, id->data, id->len);
        buf_append(&data, s->own_pk, 32);
        ok = ed25519_verify(ltpk, data.data, data.len, sig->data);
        buf_free(&data);
        if (!ok) vp_log("pair-verify: controller signature invalid");
    }
    tlv8_free(&sub);
    if (!ok) {
        put_error(out, 4);
        return;
    }

    /* Our read key is the controller's write key and vice versa. */
    hkdf_sha512(s->control_read_key, 32, s->shared, 32, "Control-Salt", "Control-Write-Encryption-Key");
    hkdf_sha512(s->control_write_key, 32, s->shared, 32, "Control-Salt", "Control-Read-Encryption-Key");
    snprintf(s->controller_id, sizeof(s->controller_id), "%s", controller_id);
    s->verified = true;
    tlv8_put_byte(out, TLV_STATE, 4);
    vp_log("pair-verify complete with controller %s", controller_id);
}

void pair_verify_handle(pair_verify_state *s, const uint8_t *body, size_t len, buf_t *out) {
    tlv8_t t;
    tlv8_decode(&t, body, len);
    int state = tlv_state(&t);
    switch (state) {
    case 1: verify_m2(s, &t, out); break;
    case 3: verify_m4(s, &t, out); break;
    default: put_error(out, state); break;
    }
    tlv8_free(&t);
}
