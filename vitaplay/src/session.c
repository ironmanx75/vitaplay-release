#include "session.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "audio.h"
#include "bplist.h"
#include "cipher.h"
#include "crypto.h"
#include "iap2_ident.h"
#include "iap2_link.h"
#include "identity.h"
#include "info.h"
#include "mfi.h"
#include "ntp.h"
#include "pairing.h"
#include "rtsp.h"
#include "screen.h"

#define PLIST_TYPE "application/x-apple-binary-plist"
#define PAIRING_TYPE "application/pairing+tlv8"
#define OCTET_TYPE "application/octet-stream"

#define STREAM_MAIN_AUDIO 100
#define STREAM_ALT_AUDIO 101
#define STREAM_MAIN_HIGH_AUDIO 102
#define STREAM_MAIN_SCREEN 110
#define STREAM_ALT_SCREEN 111
#define STREAM_DATA 130
#define IS_AUDIO_STREAM(t) ((t) == STREAM_MAIN_AUDIO || (t) == STREAM_ALT_AUDIO || (t) == STREAM_MAIN_HIGH_AUDIO)
#define IAP_DATASTREAM_UUID "E9459FD0-BCAD-4C45-820F-1E72447EF2F2"

typedef struct session {
    int fd;
    uint32_t peer_ip; /* network byte order */
    int refs;
    volatile bool closed;

    pair_setup_state setup;
    pair_verify_state verify;
    ctrl_cipher control;
    bool encrypted;

    pthread_mutex_t event_lock;
    int event_listen_fd;
    volatile int event_fd;
    ctrl_cipher event_cipher;
    volatile bool event_ready;
    int event_cseq;

    ntp_clock *ntp;
    int keepalive_fd;
    int iap_listen_fd;
    volatile int iap_fd;
    uint8_t iap_key[32];
    volatile int relay_fd;
    volatile bool streaming;
    char peer_name[64];
} session;

static session *g_current;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static void session_retain(session *s) { __atomic_add_fetch(&s->refs, 1, __ATOMIC_ACQ_REL); }

static void session_release(session *s) {
    if (__atomic_sub_fetch(&s->refs, 1, __ATOMIC_ACQ_REL) != 0) return;
    close(s->fd);
    pair_setup_free(&s->setup);
    pthread_mutex_destroy(&s->event_lock);
    free(s);
}

/* Returns the current session with a reference held, or NULL. */
static session *current_session(void) {
    pthread_mutex_lock(&g_lock);
    session *s = g_current;
    if (s) session_retain(s);
    pthread_mutex_unlock(&g_lock);
    return s;
}

static bool ends_with_ci(const char *s, const char *suffix) {
    size_t n = strlen(s), m = strlen(suffix);
    return n >= m && strcasecmp(s + n - m, suffix) == 0;
}

static void close_fd_shutdown(int fd) {
    if (fd < 0) return;
    shutdown(fd, SHUT_RDWR);
    close(fd);
}

/* ---- event channel ---- */

static volatile int g_night_mode = -1; /* -1 not chosen yet, 0 day, 1 night */
static volatile bool g_call_active;

static void send_night_mode(session *s);

/* Takes ownership of cmd. */
static bool send_command(session *s, pl_node *cmd) {
    buf_t body = {0}, plain = {0}, wire = {0};
    bplist_encode(cmd, &body);
    pl_free(cmd);

    bool sent = false;
    pthread_mutex_lock(&s->event_lock);
    if (s->event_ready) {
        char head[256];
        int n = snprintf(head, sizeof(head),
                         "POST /command RTSP/1.0\r\nContent-Type: %s\r\nContent-Length: %u\r\nCSeq: %d\r\n\r\n",
                         PLIST_TYPE, (unsigned)body.len, ++s->event_cseq);
        buf_append(&plain, head, n);
        buf_append(&plain, body.data, body.len);
        cipher_encrypt(&s->event_cipher, plain.data, plain.len, &wire);
        sent = send_all(s->event_fd, wire.data, wire.len) == 0;
        if (!sent) {
            vp_log("event command send failed");
            s->event_ready = false;
        }
    }
    pthread_mutex_unlock(&s->event_lock);
    buf_free(&body);
    buf_free(&plain);
    buf_free(&wire);
    return sent;
}

static void *event_thread(void *arg) {
    session *s = arg;
    int fd = accept(s->event_listen_fd, NULL, NULL);
    if (fd < 0) goto out;
    if (s->closed) {
        close(fd);
        goto out;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    uint8_t write_key[32], read_key[32];
    hkdf_sha512(write_key, 32, s->verify.shared, 32, "Events-Salt", "Events-Write-Encryption-Key");
    hkdf_sha512(read_key, 32, s->verify.shared, 32, "Events-Salt", "Events-Read-Encryption-Key");
    pthread_mutex_lock(&s->event_lock);
    cipher_init(&s->event_cipher, read_key, write_key);
    s->event_fd = fd;
    s->event_ready = true;
    pthread_mutex_unlock(&s->event_lock);
    vp_log("event channel connected (touch input ready)");
    send_night_mode(s);

    buf_t encrypted = {0}, plain = {0};
    uint8_t chunk[4096];
    while (!s->closed) {
        int n = recv(fd, chunk, sizeof(chunk), 0);
        if (n <= 0) break;
        buf_append(&encrypted, chunk, n);
        pthread_mutex_lock(&s->event_lock);
        int rc = cipher_decrypt(&s->event_cipher, &encrypted, &plain);
        pthread_mutex_unlock(&s->event_lock);
        if (rc != 0) {
            vp_log("event channel decrypt failed");
            break;
        }
        for (;;) {
            rtsp_msg msg;
            int used = rtsp_parse(plain.data, plain.len, &msg);
            if (used <= 0) break;
            buf_consume(&plain, used);
            /* Phone-initiated requests get an empty 200; responses to our commands are ignored. */
            if (strncmp(msg.method, "RTSP/", 5) != 0 && strncmp(msg.method, "HTTP/", 5) != 0) {
                buf_t response = {0}, wire = {0};
                rtsp_response(&response, &msg, 200, NULL, NULL, 0);
                pthread_mutex_lock(&s->event_lock);
                cipher_encrypt(&s->event_cipher, response.data, response.len, &wire);
                send_all(fd, wire.data, wire.len);
                pthread_mutex_unlock(&s->event_lock);
                buf_free(&response);
                buf_free(&wire);
            }
            rtsp_free(&msg);
        }
    }
    pthread_mutex_lock(&s->event_lock);
    s->event_ready = false;
    s->event_fd = -1;
    pthread_mutex_unlock(&s->event_lock);
    close(fd);
    buf_free(&encrypted);
    buf_free(&plain);
    vp_log("event channel closed");
out:
    session_release(s);
    return NULL;
}

static int open_event(session *s) {
    s->event_listen_fd = tcp_listen(EVENT_PORT);
    if (s->event_listen_fd < 0) return 0;
    session_retain(s);
    spawn_thread(event_thread, s);
    return EVENT_PORT;
}

/* ---- keep-alive and iAP tunnel ---- */

static void *keepalive_thread(void *arg) {
    int fd = (int)(intptr_t)arg;
    uint8_t packet[512];
    while (recv(fd, packet, sizeof(packet), 0) >= 0) {
    }
    return NULL;
}

/*
 * iAP2 tunnel (port of IapTunnel.kt + AirPlayIapTunnelStream.kt), now ON-DEVICE.
 *
 * After the Wi-Fi handoff the phone runs iAP2 again through this DataStream. We decrypt each "comm"
 * package body (raw iAP2 link bytes) and feed it to the iap2c link engine; the engine's output
 * goes back to the phone as "iAPSendMessage" event commands (the write side of the tunnel). This
 * replaces the old relay to the PlayPort bridge, so audio/Siri/now-playing are handled on the Vita.
 */
#define PACKAGE_HEADER_LEN 32
#define PACKAGE_TYPE_OFFSET 16
#define PACKAGE_TYPE_COMM 0x636f6d6dU /* "comm" */
#define MAX_PACKAGE (4 * 1024 * 1024)

static int64_t tunnel_now_ms(void) { return (int64_t)(now_us() / 1000); }

/* "02:AB:CD:EF:01:23" -> 6 bytes; placeholder on a malformed id. */
static void tunnel_parse_mac(const char *str, unsigned char out[6]) {
    static const unsigned char fallback[6] = {0x00, 0x25, 0x00, 0xAA, 0xBB, 0xCC};
    memcpy(out, fallback, 6);
    unsigned v[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) == 6)
        for (int i = 0; i < 6; i++) out[i] = (unsigned char)v[i];
}

/* Vita -> phone: one iAP2 link fragment becomes an iAPSendMessage command on the event channel. */
static bool send_iap_message(session *s, const uint8_t *data, size_t len) {
    pl_node *params = pl_dict();
    pl_set(params, "data", pl_data(data, len));
    pl_node *cmd = pl_dict();
    pl_set(cmd, "type", pl_str("iAPSendMessage"));
    pl_set(cmd, "params", params);
    return send_command(s, cmd);
}

/* Drains the iap2c link: runs due timers, sends queued output, and answers control messages. */
static void tunnel_pump(session *s, iap2_link *link, const unsigned char mac6[6], const char *serial,
                        int *ident_sent) {
    int64_t now = tunnel_now_ms();
    int64_t dl = iap2_link_next_deadline(link);
    if (dl >= 0 && now >= dl) iap2_link_advance(link, now);

    uint8_t out[1024];
    size_t n;
    while ((n = iap2_link_output(link, out, sizeof(out))) > 0) send_iap_message(s, out, n);

    iap2_link_event ev;
    while (iap2_link_poll_event(link, &ev)) {
        if (ev.type == IAP2_LINK_EVENT_CONTROL) {
            unsigned msgid = ev.len >= 6 ? ((ev.data[4] << 8) | ev.data[5]) : 0;
            vp_log("iAP2 tunnel control msgid=0x%04x len=%u", msgid, (unsigned)ev.len);
            if (msgid == 0x1d00 && !*ident_sent) { /* StartIdentification -> IdentificationInformation */
                unsigned char idmsg[768];
                int idn = iap2_build_identification(idmsg, sizeof(idmsg), mac6, g_config.name,
                                                    g_config.model, g_config.manufacturer, serial,
                                                    "1.0.0", "1.0", "com.shilapi.xcertplay", "en",
                                                    g_config.wifi_ssid);
                if (idn > 0) {
                    iap2_link_send_control(link, idmsg, (size_t)idn, tunnel_now_ms());
                    *ident_sent = 1;
                    vp_log("iAP2 tunnel tx=0x1d01 identification (%d bytes)", idn);
                }
            } else if (msgid == 0xaa00) { /* the tunnel runs MFi auth too: send our certificate */
                size_t cn = 0;
                const unsigned char *cert = mfi_cert(&cn);
                if (cert && cn > 0) {
                    unsigned char m[2048];
                    int mn = iap2_build_bytes_msg(m, sizeof(m), 0xaa01, cert, (int)cn);
                    if (mn > 0) {
                        iap2_link_send_control(link, m, (size_t)mn, tunnel_now_ms());
                        vp_log("iAP2 tunnel tx=0xaa01 certificate (%u bytes)", (unsigned)cn);
                    }
                } else {
                    vp_log("iAP2 tunnel 0xaa00 but MFi not ready (%s)", mfi_status());
                }
            } else if (msgid == 0xaa02) { /* sign the 32-byte challenge */
                const unsigned char *chal = NULL;
                int cl = iap2_get_param0(ev.data, (int)ev.len, &chal);
                if (cl == 32) {
                    unsigned char sig[64];
                    if (mfi_sign_digest(chal, sig) == 0) {
                        unsigned char m[128];
                        int mn = iap2_build_bytes_msg(m, sizeof(m), 0xaa03, sig, 64);
                        iap2_link_send_control(link, m, (size_t)mn, tunnel_now_ms());
                        vp_log("iAP2 tunnel tx=0xaa03 response (sig 64)");
                    } else {
                        vp_log("iAP2 tunnel MFi sign failed");
                    }
                } else {
                    vp_log("iAP2 tunnel 0xaa02 bad challenge len=%d", cl);
                }
            } else if (msgid == 0xaa05) {
                vp_log("iAP2 tunnel *** MFi AUTH SUCCEEDED (0xaa05) ***");
                /* Subscribe to now-playing/power/comms/call-state/route-guidance, as a head unit
                 * does after auth, so the phone treats us as a full media endpoint and sends audio. */
                for (int i = 0; i < 5; i++) {
                    unsigned char sub[128];
                    int sn = iap2_build_subscription(sub, sizeof(sub), i);
                    if (sn > 0) iap2_link_send_control(link, sub, (size_t)sn, tunnel_now_ms());
                }
                vp_log("iAP2 tunnel tx subscriptions (now-playing/power/comms/call/route)");
            } else if (msgid == 0xaa04) {
                vp_log("iAP2 tunnel MFi AUTH FAILED (0xaa04)");
            } else if (msgid == 0x5702 || msgid == 0x4e0e) {
                /* Wi-Fi/CarPlay handoff, same as the Bluetooth bootstrap: send our Wi-Fi config. */
                unsigned char m[256];
                int mn = iap2_build_wifi_config(m, sizeof(m), g_config.wifi_ssid, g_config.wifi_pass,
                                                g_config.wifi_security, g_config.wifi_channel);
                if (mn > 0) {
                    iap2_link_send_control(link, m, (size_t)mn, tunnel_now_ms());
                    vp_log("iAP2 tunnel tx=0x5703 wifi-config");
                }
            } else if (msgid == 0x4300) { /* CarPlayAvailability -> start the session on this receiver */
                unsigned char m[512];
                int mn = iap2_build_carplay_start(m, sizeof(m), g_config.wifi_ssid, g_config.wifi_pass,
                                                  g_config.wifi_security, g_config.wifi_channel,
                                                  g_config.ip, AIRPLAY_PORT, g_config.device_id,
                                                  g_identity.public_key_hex, g_config.source_version);
                if (mn > 0) {
                    iap2_link_send_control(link, m, (size_t)mn, tunnel_now_ms());
                    vp_log("iAP2 tunnel tx=0x4301 carplay-start");
                }
            }
        } else if (ev.type == IAP2_LINK_EVENT_DEAD) {
            vp_log("iAP2 tunnel link dead (%s)", ev.reason ? ev.reason : "eof");
        }
    }
    /* Flush anything the control replies queued. */
    while ((n = iap2_link_output(link, out, sizeof(out))) > 0) send_iap_message(s, out, n);
}

/* Feeds each complete "comm" package body to the iap2c link; returns bytes consumed. */
static size_t feed_packages(iap2_link *link, const uint8_t *p, size_t len, unsigned *seen) {
    size_t offset = 0;
    while (len - offset >= PACKAGE_HEADER_LEN) {
        uint32_t size = get_u32be(p + offset);
        if (size < PACKAGE_HEADER_LEN || size > MAX_PACKAGE || len - offset < size) break;
        if (get_u32be(p + offset + PACKAGE_TYPE_OFFSET) == PACKAGE_TYPE_COMM) {
            const uint8_t *iap = p + offset + PACKAGE_HEADER_LEN;
            size_t ilen = size - PACKAGE_HEADER_LEN;
            if (*seen < 8)
                vp_log("iAP2 tunnel rx %u bytes: %02x %02x %02x %02x %02x %02x %02x %02x",
                       (unsigned)ilen, ilen > 0 ? iap[0] : 0, ilen > 1 ? iap[1] : 0,
                       ilen > 2 ? iap[2] : 0, ilen > 3 ? iap[3] : 0, ilen > 4 ? iap[4] : 0,
                       ilen > 5 ? iap[5] : 0, ilen > 6 ? iap[6] : 0, ilen > 7 ? iap[7] : 0);
            iap2_link_feed(link, iap, ilen, tunnel_now_ms());
            (*seen)++;
        }
        offset += size;
    }
    return offset;
}

static void *iap_thread(void *arg) {
    session *s = arg;
    int fd = accept(s->iap_listen_fd, NULL, NULL);
    if (fd < 0) goto out;
    s->iap_fd = fd;
    vp_log("iAP2 tunnel connected; running iAP2 on-device");

    /* The tunnel is wired-profile iAP2 (zero-ack, the accessory initiates synchronization). */
    iap2_link_config cfg;
    iap2_link_config_wired(&cfg);
    iap2_link *link = iap2_link_new(&cfg);
    if (!link) { close(fd); s->iap_fd = -1; goto out; }
    iap2_link_start(link, true, tunnel_now_ms());

    unsigned char mac6[6];
    tunnel_parse_mac(g_config.device_id, mac6);
    char serial[40];
    snprintf(serial, sizeof(serial), "CARPLAYWEB-%02X%02X%02X%02X%02X%02X", mac6[0], mac6[1], mac6[2],
             mac6[3], mac6[4], mac6[5]);
    int ident_sent = 0;

    /* A short recv timeout lets the loop run iap2c timers (synchronization retransmits) too. */
    struct timeval tv = {0, 50 * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ctrl_cipher tunnel;
    cipher_init(&tunnel, s->iap_key, s->iap_key);
    buf_t encrypted = {0}, plain = {0};
    uint8_t chunk[4096];
    unsigned seen = 0;
    for (;;) {
        tunnel_pump(s, link, mac6, serial, &ident_sent);
        int n = recv(fd, chunk, sizeof(chunk), 0);
        if (n > 0) {
            buf_append(&encrypted, chunk, n);
            if (cipher_decrypt(&tunnel, &encrypted, &plain) != 0) {
                vp_log("iAP2 tunnel decrypt failed");
                break;
            }
            buf_consume(&plain, feed_packages(link, plain.data, plain.len, &seen));
            tunnel_pump(s, link, mac6, serial, &ident_sent);
        } else if (n == 0) {
            break; /* peer closed */
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            break;
        }
        /* otherwise a recv timeout: loop again to run timers */
    }
    vp_log("iAP2 tunnel closed after %u messages", seen);
    iap2_link_free(link);
    buf_free(&encrypted);
    buf_free(&plain);
    s->iap_fd = -1;
    close(fd);
out:
    session_release(s);
    return NULL;
}

/* ---- screen callbacks ---- */

static void screen_keyframe(void *ctx) {
    (void)ctx;
    session_request_keyframe();
}

static void screen_closed(void *ctx) {
    (void)ctx;
    session *s = current_session();
    if (!s) return;
    vp_log("screen stream closed; ending session");
    shutdown(s->fd, SHUT_RDWR);
    session_release(s);
}

/* ---- SETUP / TEARDOWN ---- */

static pl_node *echo_uint(const pl_node *value) {
    if (value && value->type == PL_UINT) return pl_uint(value->v.u);
    if (value && value->type == PL_INT) return pl_int(value->v.i);
    return pl_int(0);
}

static pl_node *setup_stream(session *s, const pl_node *stream) {
    int64_t type;
    if (!pl_get_int(stream, "type", &type)) return NULL;
    char desc[200];
    pl_describe(stream, desc, sizeof(desc));
    vp_log("SETUP stream type=%lld %s", (long long)type, desc);

    if (type == STREAM_MAIN_SCREEN) {
        uint64_t connection_id;
        if (!pl_get_u64(stream, "streamConnectionID", &connection_id)) {
            vp_log("screen stream without streamConnectionID");
            return NULL;
        }
        char salt[64];
        snprintf(salt, sizeof(salt), "DataStream-Salt%llu", (unsigned long long)connection_id);
        uint8_t key[32];
        hkdf_sha512(key, 32, s->verify.shared, 32, salt, "DataStream-Output-Encryption-Key");
        screen_callbacks callbacks = {screen_keyframe, screen_closed, NULL};
        int port = screen_start(key, callbacks);
        if (port < 0) return NULL;
        s->streaming = true;
        pl_node *r = pl_dict();
        pl_set(r, "type", pl_int(type));
        pl_set(r, "dataPort", pl_int(port));
        return r;
    }

    if (type == STREAM_DATA) {
        if (strcasecmp(pl_get_str(stream, "clientTypeUUID"), IAP_DATASTREAM_UUID) != 0) return NULL;
        uint64_t seed;
        if (!pl_get_u64(stream, "seed", &seed)) {
            vp_log("iAP2 data stream without a seed");
            return NULL;
        }
        char salt[64];
        snprintf(salt, sizeof(salt), "DataStream-Salt%llu", (unsigned long long)seed);
        hkdf_sha512(s->iap_key, 32, s->verify.shared, 32, salt, "DataStream-Output-Encryption-Key");
        close_fd_shutdown(s->iap_listen_fd);
        s->iap_listen_fd = tcp_listen(IAP_TUNNEL_PORT);
        if (s->iap_listen_fd < 0) return NULL;
        session_retain(s);
        spawn_thread(iap_thread, s);
        pl_node *r = pl_dict();
        pl_set(r, "type", pl_int(STREAM_DATA));
        pl_set(r, "streamID", pl_int(1));
        pl_set(r, "dataPort", pl_int(IAP_TUNNEL_PORT));
        const pl_node *id = pl_get(stream, "streamConnectionID");
        if (id) pl_set(r, "streamConnectionID", echo_uint(id));
        return r;
    }

    if (IS_AUDIO_STREAM(type)) {
        uint64_t connection_id = 0;
        pl_get_u64(stream, "streamConnectionID", &connection_id);
        char salt[64];
        snprintf(salt, sizeof(salt), "DataStream-Salt%llu", (unsigned long long)connection_id);
        uint8_t key[32];
        hkdf_sha512(key, 32, s->verify.shared, 32, salt, "DataStream-Output-Encryption-Key");
        return audio_stream_setup((int)type, stream, key);
    }

    vp_log("stream type %lld not supported", (long long)type);
    return NULL;
}

static int handle_setup(session *s, const rtsp_msg *req, buf_t *body) {
    pl_node *dict = bplist_decode(req->body, req->body_len);
    if (!dict || dict->type != PL_DICT) {
        pl_free(dict);
        return 400;
    }
    pl_node *response = pl_dict();
    const pl_node *streams = pl_get(dict, "streams");
    if (streams && streams->type == PL_ARRAY) {
        pl_node *result = pl_array();
        for (size_t i = 0; i < streams->count; i++) {
            pl_node *entry = setup_stream(s, streams->items[i]);
            if (entry) pl_push(result, entry);
        }
        pl_set(response, "streams", result);
    } else {
        snprintf(s->peer_name, sizeof(s->peer_name), "%s", pl_get_str(dict, "name"));
        vp_log("SETUP from \"%s\" model=%s os=%s", s->peer_name, pl_get_str(dict, "model"),
               pl_get_str(dict, "osVersion"));
        { /* Diagnostic: dump the whole session SETUP to find any audio-capability negotiation. */
            char desc[1600];
            pl_describe(dict, desc, sizeof(desc));
            vp_log("session SETUP body: %s", desc);
        }
        int64_t timing_port = 0;
        pl_get_int(dict, "timingPort", &timing_port);
        ntp_stop(s->ntp);
        s->ntp = ntp_start(s->peer_ip, (int)timing_port);
        pl_set(response, "timingPort", pl_int(TIMING_PORT));
        pl_set(response, "eventPort", pl_int(open_event(s)));
        if (pl_truthy(pl_get(dict, "keepAliveLowPower"))) {
            s->keepalive_fd = udp_bind(KEEPALIVE_PORT);
            if (s->keepalive_fd >= 0) {
                spawn_thread(keepalive_thread, (void *)(intptr_t)s->keepalive_fd);
                pl_set(response, "keepAlivePort", pl_int(KEEPALIVE_PORT));
            }
        }
        pl_node *features = pl_array();
        pl_push(features, pl_str("iAPChannel"));
        pl_push(features, pl_str("viewAreas"));
        pl_set(response, "enabledFeatures", features);
    }
    bplist_encode(response, body);
    pl_free(response);
    pl_free(dict);
    return 200;
}

static void handle_teardown(session *s, const rtsp_msg *req) {
    pl_node *dict = bplist_decode(req->body, req->body_len);
    const pl_node *streams = pl_get(dict, "streams");
    bool stop_screen = !streams || streams->type != PL_ARRAY || streams->count == 0;
    if (!stop_screen) {
        for (size_t i = 0; i < streams->count; i++) {
            int64_t type;
            if (!pl_get_int(streams->items[i], "type", &type)) continue;
            if (type == STREAM_MAIN_SCREEN) stop_screen = true;
            if (IS_AUDIO_STREAM(type)) audio_stream_stop((int)type);
        }
    }
    if (stop_screen && s->streaming) {
        screen_stop();
        s->streaming = false;
    }
    if (stop_screen) audio_stop_all(); /* a full teardown ends every audio stream too */
    vp_log("TEARDOWN (screen %s)", stop_screen ? "stopped" : "kept");
    pl_free(dict);
}

/* modesChanged: app state 2 is a phone call; entity 1 means the phone (CarPlay) owns it. */
static void track_call_state(const pl_node *params) {
    const pl_node *states = pl_get(params, "appStates");
    if (!states || states->type != PL_ARRAY) return;
    for (size_t i = 0; i < states->count; i++) {
        int64_t id = 0, entity = 0;
        if (!pl_get_int(states->items[i], "appStateID", &id) || id != 2) continue;
        pl_get_int(states->items[i], "entity", &entity);
        bool active = entity == 1;
        if (active != g_call_active) vp_log("phone call %s", active ? "started" : "ended");
        g_call_active = active;
    }
}

static void handle_command(const rtsp_msg *req) {
    pl_node *dict = bplist_decode(req->body, req->body_len);
    /* The whole command, not just its type: modesChanged says who owns the screen and audio. */
    char desc[400];
    if (dict) pl_describe(dict, desc, sizeof(desc));
    vp_log("phone command: %s", dict ? desc : "?");
    if (dict && strcmp(pl_get_str(dict, "type"), "modesChanged") == 0) track_call_state(pl_get(dict, "params"));
    pl_free(dict);
}

/* ---- control channel ---- */

static void handle_request(session *s, const rtsp_msg *req, buf_t *out) {
    int status = 200;
    const char *content_type = NULL;
    buf_t body = {0};
    const char *path = req->path;
    bool quiet = ends_with_ci(path, "/feedback") || ends_with_ci(path, "/command");
    if (!quiet) vp_log("rx %s %s (%u bytes)", req->method, path, (unsigned)req->body_len);

    if (strcmp(req->method, "SETUP") == 0) {
        status = handle_setup(s, req, &body);
        if (status == 200) content_type = PLIST_TYPE;
    } else if (strcmp(req->method, "RECORD") == 0) {
        vp_log("CarPlay session active");
    } else if (strcmp(req->method, "TEARDOWN") == 0) {
        handle_teardown(s, req);
    } else if (ends_with_ci(path, "/pair-setup")) {
        pair_setup_handle(&s->setup, req->body, req->body_len, &body);
        content_type = PAIRING_TYPE;
    } else if (ends_with_ci(path, "/pair-verify")) {
        pair_verify_handle(&s->verify, req->body, req->body_len, &body);
        content_type = PAIRING_TYPE;
    } else if (ends_with_ci(path, "/auth-setup")) {
        if (mfi_auth_setup(req->body, req->body_len, &body) == 0) content_type = OCTET_TYPE;
        else {
            vp_log("auth-setup refused: %s", mfi_status());
            status = 400;
        }
    } else if (ends_with_ci(path, "/info")) {
        pl_node *info = info_build(&g_config);
        const pl_node *af = pl_get(info, "audioFormats");
        const pl_node *al = pl_get(info, "audioLatencies");
        bplist_encode(info, &body);
        vp_log("/info sent: %u bytes, audioFormats=%d audioLatencies=%d features=0x%llx",
               (unsigned)body.len, af && af->type == PL_ARRAY ? (int)af->count : -1,
               al && al->type == PL_ARRAY ? (int)al->count : -1,
               (unsigned long long)0x615653aee2LL);
        pl_free(info);
        content_type = PLIST_TYPE;
    } else if (strcmp(req->method, "POST") == 0 && ends_with_ci(path, "/command")) {
        handle_command(req);
    }
    rtsp_response(out, req, status, content_type, body.data, body.len);
    buf_free(&body);
}

static void session_teardown(session *s) {
    pthread_mutex_lock(&g_lock);
    if (g_current == s) g_current = NULL;
    pthread_mutex_unlock(&g_lock);
    g_call_active = false;
    s->closed = true;
    if (s->streaming) screen_stop();
    s->streaming = false;
    audio_stop_all();
    ntp_stop(s->ntp);
    s->ntp = NULL;

    pthread_mutex_lock(&s->event_lock);
    s->event_ready = false;
    int event_fd = s->event_fd;
    pthread_mutex_unlock(&s->event_lock);
    close_fd_shutdown(s->event_listen_fd);
    if (event_fd >= 0) shutdown(event_fd, SHUT_RDWR);

    close_fd_shutdown(s->keepalive_fd);
    close_fd_shutdown(s->iap_listen_fd);
    int iap_fd = s->iap_fd;
    if (iap_fd >= 0) shutdown(iap_fd, SHUT_RDWR);
    int relay_fd = s->relay_fd;
    if (relay_fd >= 0) shutdown(relay_fd, SHUT_RDWR);
    shutdown(s->fd, SHUT_RDWR);
    vp_log("session ended");
}

static void *control_thread(void *arg) {
    session *s = arg;
    buf_t encrypted = {0}, plain = {0}, out = {0}, wire = {0};
    uint8_t *chunk = malloc(16 * 1024);
    while (!s->closed) {
        int n = recv(s->fd, chunk, 16 * 1024, 0);
        if (n <= 0) break;
        if (s->encrypted) {
            buf_append(&encrypted, chunk, n);
            if (cipher_decrypt(&s->control, &encrypted, &plain) != 0) {
                vp_log("control channel decrypt failed");
                break;
            }
        } else {
            buf_append(&plain, chunk, n);
        }

        int used;
        for (;;) {
            rtsp_msg req;
            used = rtsp_parse(plain.data, plain.len, &req);
            if (used <= 0) break;
            buf_consume(&plain, used);
            buf_clear(&out);
            handle_request(s, &req, &out);
            rtsp_free(&req);

            const buf_t *send_buf = &out;
            if (s->encrypted) {
                buf_clear(&wire);
                cipher_encrypt(&s->control, out.data, out.len, &wire);
                send_buf = &wire;
            }
            if (send_all(s->fd, send_buf->data, send_buf->len) != 0) {
                used = -1;
                break;
            }
            if (!s->encrypted && s->verify.verified) {
                /* Everything after the final pair-verify response is encrypted. */
                cipher_init(&s->control, s->verify.control_read_key, s->verify.control_write_key);
                s->encrypted = true;
                buf_append(&encrypted, plain.data, plain.len);
                buf_clear(&plain);
                vp_log("control channel encrypted");
            }
        }
        if (used < 0) break;
    }
    free(chunk);
    buf_free(&encrypted);
    buf_free(&plain);
    buf_free(&out);
    buf_free(&wire);
    session_teardown(s);
    session_release(s);
    return NULL;
}

static void *server_thread(void *arg) {
    (void)arg;
    int listen_fd = tcp_listen(AIRPLAY_PORT);
    if (listen_fd < 0) {
        vp_log("cannot listen on AirPlay port %d", AIRPLAY_PORT);
        return NULL;
    }
    vp_log("AirPlay receiver listening on %s:%d", g_config.ip, AIRPLAY_PORT);
    for (;;) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        int fd = accept(listen_fd, (struct sockaddr *)&addr, &addr_len);
        if (fd < 0) {
            usleep(100 * 1000);
            continue;
        }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        vp_log("phone connected from %s", inet_ntoa(addr.sin_addr));

        session *s = calloc(1, sizeof(*s));
        if (!s) {
            close(fd);
            continue;
        }
        s->fd = fd;
        s->peer_ip = addr.sin_addr.s_addr;
        s->refs = 1;
        s->event_listen_fd = s->event_fd = s->keepalive_fd = -1;
        s->iap_listen_fd = s->iap_fd = s->relay_fd = -1;
        pthread_mutex_init(&s->event_lock, NULL);

        pthread_mutex_lock(&g_lock);
        session *old = g_current;
        if (old) session_retain(old);
        g_current = s;
        pthread_mutex_unlock(&g_lock);
        if (old) {
            vp_log("replacing the previous session");
            shutdown(old->fd, SHUT_RDWR);
            session_release(old);
        }
        spawn_thread(control_thread, s);
    }
    return NULL;
}

int session_server_start(void) { return spawn_thread(server_thread, NULL); }

session_state session_current_state(void) {
    session *s = current_session();
    if (!s) return SESSION_IDLE;
    session_state state = s->streaming ? SESSION_STREAMING
                          : s->encrypted ? SESSION_VERIFIED
                                         : SESSION_CONNECTED;
    session_release(s);
    return state;
}

void session_peer_name(char *out, size_t max) {
    session *s = current_session();
    snprintf(out, max, "%s", s && s->peer_name[0] ? s->peer_name : "iPhone");
    if (s) session_release(s);
}

static void send_hid(uint32_t uid, const uint8_t *report, size_t len) {
    session *s = current_session();
    if (!s) return;
    if (s->event_ready) {
        char uuid[16];
        snprintf(uuid, sizeof(uuid), "%x", (unsigned)uid);
        pl_node *cmd = pl_dict();
        pl_set(cmd, "type", pl_str("hidSendReport"));
        pl_set(cmd, "uuid", pl_str(uuid));
        pl_set(cmd, "hidReport", pl_data(report, len));
        send_command(s, cmd);
    }
    session_release(s);
}

void session_send_touch(const touch_contact contacts[TOUCH_CONTACTS]) {
    uint8_t report[TOUCH_CONTACTS * 6];
    hid_touch_report(report, contacts);
    send_hid(TOUCH_HID_UID, report, sizeof(report));
}

void session_send_knob(const knob_state *state) {
    uint8_t report[4];
    hid_knob_report(report, state);
    send_hid(KNOB_HID_UID, report, sizeof(report));
}

static void send_hid_press(uint32_t uid, int index) {
    uint8_t report = (uint8_t)index;
    send_hid(uid, &report, 1);
    report = 0;
    send_hid(uid, &report, 1);
}

void session_send_media(int index) { send_hid_press(MEDIA_HID_UID, index); }

void session_send_telephony(int index) { send_hid_press(TELEPHONY_HID_UID, index); }

void session_request_siri(void) {
    session *s = current_session();
    if (!s) return;
    /* A press (2) and its release (3), as PlayPort sends for a voice key. */
    for (int action = 2; action <= 3; action++) {
        pl_node *params = pl_dict();
        pl_set(params, "siriAction", pl_int(action));
        pl_node *cmd = pl_dict();
        pl_set(cmd, "type", pl_str("requestSiri"));
        pl_set(cmd, "params", params);
        send_command(s, cmd);
    }
    session_release(s);
}

static void send_night_mode(session *s) {
    int night = g_night_mode;
    if (night < 0) return;
    pl_node *params = pl_dict();
    pl_set(params, "nightMode", pl_bool(night == 1));
    pl_node *cmd = pl_dict();
    pl_set(cmd, "type", pl_str("setNightMode"));
    pl_set(cmd, "params", params);
    bool sent = send_command(s, cmd);
    vp_log("night mode %s (sent=%d)", night ? "on" : "off", sent);
}

void session_set_night_mode(bool night) {
    if (g_night_mode == (night ? 1 : 0)) return;
    g_night_mode = night ? 1 : 0;
    session *s = current_session();
    if (!s) return;
    send_night_mode(s);
    session_release(s);
}

bool session_call_active(void) { return g_call_active; }

void session_request_keyframe(void) {
    session *s = current_session();
    if (!s) return;
    pl_node *cmd = pl_dict();
    pl_set(cmd, "type", pl_str("forceKeyFrame"));
    bool sent = send_command(s, cmd);
    vp_log("requested keyframe (sent=%d)", sent);
    session_release(s);
}
