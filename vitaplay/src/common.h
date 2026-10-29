/*
 * VitaPlay - CarPlay receiver for PS Vita.
 * Port of the PlayPort / DiPlay / xcertplay protocol stack (GPL-3.0).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define APP_DIR "ux0:data/VitaPlay"
#ifndef AIRPLAY_PORT
#define AIRPLAY_PORT 7000 /* host tests override this; macOS's own AirPlay Receiver holds 7000 */
#endif

/* Fixed side-channel ports; the phone learns them from the SETUP responses. */
#define TIMING_PORT 7010
#define EVENT_PORT 7011
#define KEEPALIVE_PORT 7012
#define SCREEN_PORT 7100
#define IAP_TUNNEL_PORT 7130

/** Accessory configuration advertised in mDNS and /info. */
typedef struct {
    char name[64];
    char device_id[18];      /* "02:AB:CD:EF:01:23" */
    char bt_mac[18];         /* Bluetooth address of the bootstrap helper */
    char model[32];
    char manufacturer[32];
    char source_version[16];
    char ip[16];
    char relay_host[16]; /* iAP2 relay (PlayPort on a Mac); empty = none */
    int relay_port;
    char wifi_ssid[33];  /* Wi-Fi the phone joins for wireless CarPlay (0x5703/0x4301) */
    char wifi_pass[64];  /* its passphrase; the Vita cannot read this, so config.txt supplies it */
    int wifi_channel;    /* 0 when unknown */
    int wifi_security;   /* 0 none, 1 WEP, 2 WPA/WPA2, 3 WPA3-transition, 4 WPA3 */
    int width;
    int height;
    int fps;
    int night_mode; /* -1 automatic by the Vita's clock, 0 always day, 1 always night */
} vp_config;

extern vp_config g_config;

/* Growable byte buffer. */
typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} buf_t;

void buf_reserve(buf_t *b, size_t extra);
void buf_append(buf_t *b, const void *data, size_t len);
void buf_append_str(buf_t *b, const char *s);
void buf_consume(buf_t *b, size_t n);
void buf_clear(buf_t *b);
void buf_free(buf_t *b);

/* Logging to screen ring buffer and APP_DIR/log.txt. */
void log_init(void);
void vp_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
int log_snapshot(char lines[][96], int max);

uint64_t now_us(void);
void rand_bytes(void *out, size_t len);
void hex_encode(char *out, const uint8_t *in, size_t len); /* lowercase, NUL-terminated */
int hex_decode(uint8_t *out, size_t max, const char *in);  /* returns bytes or -1 */

/* Socket helpers. */
int tcp_listen(int port);
int udp_bind(int port);
int send_all(int fd, const void *data, size_t len);
int recv_full(int fd, void *data, size_t len); /* 1 ok, 0 EOF, -1 error */

/* Starts a detached thread with a stack large enough for bignum work. */
int spawn_thread(void *(*fn)(void *), void *arg);

static inline void put_u32be(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}
static inline uint32_t get_u32be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static inline uint32_t get_u32le(const uint8_t *p) {
    return p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint16_t get_u16be(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
