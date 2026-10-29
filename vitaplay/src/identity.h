/* Long-term AirPlay Ed25519 identity and the paired-controller store. */
#pragma once

#include "common.h"

typedef struct {
    uint8_t seed[32];
    uint8_t public_key[32];
    char public_key_hex[65];
    char pairing_id[37]; /* UUID */
} airplay_identity;

extern airplay_identity g_identity;

/* Loads APP_DIR/identity.txt or creates it. */
int identity_load_or_create(void);
/* MAC-style device id derived from the public key, as PlayPort does. */
void identity_device_id(char out[18]);

void pairings_load(void);
void pairings_save(const char *controller_id, const uint8_t ltpk[32]);
bool pairings_get(const char *controller_id, uint8_t ltpk[32]);
int pairings_count(void);
