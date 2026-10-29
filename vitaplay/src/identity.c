#include "identity.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"

#define IDENTITY_FILE APP_DIR "/identity.txt"
#define PAIRINGS_FILE APP_DIR "/pairings.txt"
#define MAX_PAIRINGS 16

airplay_identity g_identity;

static void make_uuid(char out[37]) {
    uint8_t b[16];
    rand_bytes(b, sizeof(b));
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12],
             b[13], b[14], b[15]);
}

int identity_load_or_create(void) {
    char seed_hex[65] = {0};
    FILE *f = fopen(IDENTITY_FILE, "r");
    if (f) {
        char line[128];
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\r\n")] = 0;
            if (strncmp(line, "seed=", 5) == 0) snprintf(seed_hex, sizeof(seed_hex), "%s", line + 5);
            if (strncmp(line, "pairing_id=", 11) == 0)
                snprintf(g_identity.pairing_id, sizeof(g_identity.pairing_id), "%s", line + 11);
        }
        fclose(f);
    }
    if (hex_decode(g_identity.seed, 32, seed_hex) != 32 || !g_identity.pairing_id[0]) {
        rand_bytes(g_identity.seed, 32);
        make_uuid(g_identity.pairing_id);
        hex_encode(seed_hex, g_identity.seed, 32);
        f = fopen(IDENTITY_FILE, "w");
        if (!f) return -1;
        fprintf(f, "# VitaPlay AirPlay identity - keep this file secret\nseed=%s\npairing_id=%s\n",
                seed_hex, g_identity.pairing_id);
        fclose(f);
        vp_log("created new AirPlay identity");
    }
    ed25519_public(g_identity.public_key, g_identity.seed);
    hex_encode(g_identity.public_key_hex, g_identity.public_key, 32);
    return 0;
}

void identity_device_id(char out[18]) {
    uint8_t digest[32];
    sha256_parts(digest, g_identity.public_key, (size_t)32, NULL);
    snprintf(out, 18, "02:%02X:%02X:%02X:%02X:%02X", digest[0], digest[1], digest[2], digest[3],
             digest[4]);
}

typedef struct {
    char id[64];
    uint8_t ltpk[32];
} pairing_entry;

static pairing_entry pairings[MAX_PAIRINGS];
static int pairing_total;
static pthread_mutex_t pairing_lock = PTHREAD_MUTEX_INITIALIZER;

void pairings_load(void) {
    FILE *f = fopen(PAIRINGS_FILE, "r");
    if (!f) return;
    char line[256];
    pthread_mutex_lock(&pairing_lock);
    while (pairing_total < MAX_PAIRINGS && fgets(line, sizeof(line), f)) {
        char id[64], hex[65];
        if (sscanf(line, "%63s %64s", id, hex) != 2) continue;
        pairing_entry *e = &pairings[pairing_total];
        if (hex_decode(e->ltpk, 32, hex) != 32) continue;
        snprintf(e->id, sizeof(e->id), "%s", id);
        pairing_total++;
    }
    pthread_mutex_unlock(&pairing_lock);
    fclose(f);
}

static void pairings_write_locked(void) {
    FILE *f = fopen(PAIRINGS_FILE, "w");
    if (!f) return;
    for (int i = 0; i < pairing_total; i++) {
        char hex[65];
        hex_encode(hex, pairings[i].ltpk, 32);
        fprintf(f, "%s %s\n", pairings[i].id, hex);
    }
    fclose(f);
}

void pairings_save(const char *controller_id, const uint8_t ltpk[32]) {
    pthread_mutex_lock(&pairing_lock);
    int slot = -1;
    for (int i = 0; i < pairing_total; i++) {
        if (strcmp(pairings[i].id, controller_id) == 0) slot = i;
    }
    if (slot < 0) {
        if (pairing_total == MAX_PAIRINGS) {
            memmove(&pairings[0], &pairings[1], sizeof(pairings[0]) * (MAX_PAIRINGS - 1));
            pairing_total--;
        }
        slot = pairing_total++;
    }
    snprintf(pairings[slot].id, sizeof(pairings[slot].id), "%s", controller_id);
    memcpy(pairings[slot].ltpk, ltpk, 32);
    pairings_write_locked();
    pthread_mutex_unlock(&pairing_lock);
}

bool pairings_get(const char *controller_id, uint8_t ltpk[32]) {
    bool found = false;
    pthread_mutex_lock(&pairing_lock);
    for (int i = 0; i < pairing_total; i++) {
        if (strcmp(pairings[i].id, controller_id) == 0) {
            memcpy(ltpk, pairings[i].ltpk, 32);
            found = true;
        }
    }
    pthread_mutex_unlock(&pairing_lock);
    return found;
}

int pairings_count(void) { return pairing_total; }
