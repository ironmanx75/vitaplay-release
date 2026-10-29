/*
 * Software MFi accessory identity and the /auth-setup MFiSAP responder.
 * Ports of LocalMfiAuthenticationClient.kt and MfiSapAuthSetup.kt.
 *
 * Expects APP_DIR/offline-mfi/identity.pk8 (PKCS#8 EC P-256 key) and certificate.p7b.
 * These files are not shipped with VitaPlay.
 */
#pragma once

#include "common.h"

/* Returns 0 when a matching key and certificate were loaded. */
int mfi_load(void);
bool mfi_ready(void);
const char *mfi_status(void);

/* 64-byte raw r||s ECDSA signature over an already-hashed 32-byte digest. */
int mfi_sign_digest(const uint8_t digest[32], uint8_t sig[64]);

/* The raw accessory certificate (certificate.p7b) for iAP2 AuthenticationCertificate (0xAA01);
 * returns NULL with *len = 0 when no identity is loaded. */
const uint8_t *mfi_cert(size_t *len);

/* Handles an /auth-setup body; returns 0 and fills out, or -1 for a 400 response. */
int mfi_auth_setup(const uint8_t *body, size_t len, buf_t *out);
