/*
 * Host build of the VitaPlay protocol stack for end-to-end tests with tools/FakePhone.java.
 * Uses the real src/ modules except video.c (replaced below) and main.c.
 *
 *   host_vitaplay <ip> <seconds>
 */
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "../../src/common.h"
#include "../../src/crypto.h"
#include "../../src/identity.h"
#include "../../src/mdns.h"
#include "../../src/mfi.h"
#include "../../src/session.h"
#include "../../src/video.h"

/* ---- psp2 stand-ins ---- */

uint64_t sceKernelGetProcessTimeWide(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

int sceKernelGetRandomNumber(void *output, size_t size) {
    arc4random_buf(output, size);
    return 0;
}

/* ---- video stand-in: validates what the decoder would receive ---- */

static uint32_t frames;

int video_init(int width, int height) { return 0; }
void video_shutdown(void) {}
void video_reset(void) { frames = 0; }
vita2d_texture *video_front(void) { return NULL; }
uint32_t video_frames_decoded(void) { return frames; }

static bool pending_sets;

void video_set_config(const uint8_t *avcc, size_t len) {
    /* Same parsing as video.c, checked rather than decoded. */
    size_t pos = 5, sets = 0;
    int sps = len > 5 ? avcc[pos++] & 0x1f : 0;
    for (int i = 0; i < sps && pos + 2 <= len; i++) pos += 2 + get_u16be(avcc + pos), sets++;
    int pps = pos < len ? avcc[pos++] : 0;
    for (int i = 0; i < pps && pos + 2 <= len; i++) pos += 2 + get_u16be(avcc + pos), sets++;
    pending_sets = sets > 0;
    vp_log("TEST video config: %d SPS + %d PPS parsed=%s", sps, pps, pos == len ? "exact" : "MISMATCH");
}

int video_decode(const uint8_t *annexb, size_t len) {
    bool annex_b = len >= 5 && annexb[0] == 0 && annexb[1] == 0 && annexb[2] == 0 && annexb[3] == 1;
    frames++;
    vp_log("TEST frame %u: %u bytes annexB=%d nal=0x%02x sps_pps_prepended=%d", frames, (unsigned)len,
           annex_b, len > 4 ? annexb[4] : 0, pending_sets);
    pending_sets = false;
    return 0;
}

static void load_config(const char *ip) {
    vp_config *c = &g_config;
    snprintf(c->name, sizeof(c->name), "VitaPlay");
    snprintf(c->model, sizeof(c->model), "VitaPlay");
    snprintf(c->manufacturer, sizeof(c->manufacturer), "VitaPlay");
    snprintf(c->source_version, sizeof(c->source_version), "366.0");
    identity_device_id(c->device_id);
    snprintf(c->bt_mac, sizeof(c->bt_mac), "%s", c->device_id);
    snprintf(c->ip, sizeof(c->ip), "%s", ip);
    c->width = 960;
    c->height = 544;
    c->fps = 60;
}

int main(int argc, char **argv) {
    const char *ip = argc > 1 ? argv[1] : "127.0.0.1";
    int seconds = argc > 2 ? atoi(argv[2]) : 20;
    const char *relay_port = argc > 3 ? argv[3] : NULL; /* iAP2 relay on 127.0.0.1 */
    signal(SIGPIPE, SIG_IGN);
    mkdir("ux0:data", 0755);
    mkdir(APP_DIR, 0755);

    log_init();
    if (crypto_setup() != 0) return 1;
    identity_load_or_create();
    pairings_load();
    mfi_load();
    load_config(ip);
    if (relay_port) {
        snprintf(g_config.relay_host, sizeof(g_config.relay_host), "127.0.0.1");
        g_config.relay_port = atoi(relay_port);
    }
    printf("device_id=%s\npublic_key=%s\npairing_id=%s\n%s\n", g_config.device_id,
           g_identity.public_key_hex, g_identity.pairing_id, mfi_status());
    fflush(stdout);
    mdns_start();
    session_server_start();

    /* Mimic main.c: once streaming, send a touch down/up through the event channel. */
    bool touched = false;
    for (int tick = 0; tick < seconds * 10; tick++) {
        usleep(100 * 1000);
        if (!touched && session_current_state() == SESSION_STREAMING && video_frames_decoded() >= 2) {
            touch_contact down[TOUCH_CONTACTS] = {{true, 480, 272}, {false, 0, 0}};
            touch_contact up[TOUCH_CONTACTS] = {{false, 480, 272}, {false, 0, 0}};
            session_send_touch(down);
            session_send_touch(up);
            knob_state knob = {.select = true};
            session_send_knob(&knob);
            touched = true;
            vp_log("TEST sent touch down/up and knob select");
        }
    }
    return 0;
}
