#include "screen.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "crypto.h"
#include "video.h"

#define HEADER_LEN 128
#define OPCODE_OFFSET 4
#define OP_VIDEO_FRAME 0
#define OP_VIDEO_CONFIG 1
#define MAX_BODY (8 * 1024 * 1024)
#define STATS_WINDOW_US 10000000 /* every log line is flushed to the memory card */

typedef struct {
    uint8_t key[32];
    int listen_fd;
    volatile int client_fd;
    volatile bool stopping;
    screen_callbacks callbacks;
} screen_ctx;

static screen_ctx *current;

/* Counters for the periodic "video stats" log line, all touched only by the screen thread. */
typedef struct {
    uint64_t window_start;
    uint64_t last_frame;
    uint32_t frames, bytes, failures, shown_at_start;
    uint64_t wait_us, decrypt_us, decode_us;
    uint32_t max_decrypt_us, max_decode_us, max_gap_us;
} video_stats;

static void stats_frame(video_stats *st, uint64_t arrived, uint32_t size) {
    if (st->last_frame && arrived - st->last_frame > st->max_gap_us)
        st->max_gap_us = (uint32_t)(arrived - st->last_frame);
    st->last_frame = arrived;
    st->frames++;
    st->bytes += size;
}

/* Logs one line per STATS_WINDOW_US while frames arrive, then starts a new window. */
static void stats_tick(video_stats *st, uint64_t now) {
    if (!st->window_start) {
        st->window_start = now;
        st->shown_at_start = video_frames_decoded();
        return;
    }
    uint64_t elapsed = now - st->window_start;
    if (elapsed < STATS_WINDOW_US) return;
    if (st->frames) {
        uint32_t shown = video_frames_decoded() - st->shown_at_start;
        vp_log("video stats: %u recv %u shown %u fail | %u kbit/s | decrypt avg %llu max %u us | "
               "decode avg %llu max %u us | net wait %llu ms | max gap %u ms",
               st->frames, shown, st->failures,
               (unsigned)((uint64_t)st->bytes * 8 * 1000 / elapsed),
               (unsigned long long)(st->decrypt_us / st->frames), st->max_decrypt_us,
               (unsigned long long)(st->decode_us / st->frames), st->max_decode_us,
               (unsigned long long)(st->wait_us / 1000), st->max_gap_us / 1000);
    }
    uint64_t last = st->last_frame;
    memset(st, 0, sizeof(*st));
    st->window_start = now;
    st->last_frame = last;
    st->shown_at_start = video_frames_decoded();
}

/* Replaces each four-byte NAL length with a start code, only if every length is valid. */
static void length_prefixed_to_annexb(uint8_t *p, size_t len) {
    if (len < 4 || (p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 1)) return;
    size_t offset = 0;
    while (offset + 4 <= len) {
        uint32_t n = get_u32be(p + offset);
        offset += 4;
        if (n == 0 || offset + n > len) return;
        offset += n;
    }
    if (offset != len) return;
    offset = 0;
    while (offset + 4 <= len) {
        uint32_t n = get_u32be(p + offset);
        p[offset] = 0;
        p[offset + 1] = 0;
        p[offset + 2] = 0;
        p[offset + 3] = 1;
        offset += 4 + n;
    }
}

/* Finds the avcC record inside a VideoConfig payload. */
static void handle_config(const uint8_t *body, size_t len) {
    for (size_t i = 4; i + 4 <= len; i++) {
        if (memcmp(body + i, "avcC", 4) == 0) {
            video_set_config(body + i + 4, len - i - 4);
            return;
        }
        if (memcmp(body + i, "hvcC", 4) == 0) {
            vp_log("phone sent HEVC config; only H.264 is supported");
            return;
        }
    }
    /* Bare avcC: version 1 and an SPS NAL type in the first entry. */
    if (len >= 9 && body[0] == 1 && (body[8] & 0x1f) == 7) video_set_config(body, len);
    else vp_log("unrecognised video config (%u bytes)", (unsigned)len);
}

static void *screen_thread(void *arg) {
    screen_ctx *s = arg;
    int fd = accept(s->listen_fd, NULL, NULL);
    if (fd < 0) goto out;
    s->client_fd = fd;
    vp_log("screen stream connected");

    uint8_t header[HEADER_LEN];
    uint8_t *body = NULL, *plain = NULL;
    size_t capacity = 0;
    uint64_t counter = 0;
    int failures = 0;
    video_stats stats = {0};
    video_reset();

    while (!s->stopping) {
        uint64_t wait_start = now_us();
        if (recv_full(fd, header, HEADER_LEN) != 1) break;
        uint32_t size = get_u32le(header);
        if (size > MAX_BODY) break;
        if (size > capacity) {
            /* Old contents are not needed, so replace rather than realloc. */
            free(body);
            free(plain);
            capacity = size + 64 * 1024;
            body = malloc(capacity);
            plain = malloc(capacity);
            if (!body || !plain) {
                vp_log("out of memory for a %u-byte video frame", (unsigned)size);
                break;
            }
        }
        if (size && recv_full(fd, body, size) != 1) break;
        uint64_t arrived = now_us();

        switch (header[OPCODE_OFFSET]) {
        case OP_VIDEO_FRAME: {
            stats.wait_us += arrived - wait_start;
            stats_frame(&stats, arrived, size);
            const uint8_t *frame = body;
            size_t frame_len = size;
            if (size >= AEAD_TAG) {
                uint8_t nonce[12];
                nonce64(nonce, counter++);
                if (chacha_open(plain, s->key, nonce, body, size, header, HEADER_LEN) != 0) {
                    vp_log("screen frame decrypt failed (counter %llu)", (unsigned long long)counter - 1);
                    goto done;
                }
                frame = plain;
                frame_len = size - AEAD_TAG;
            }
            uint64_t decrypted = now_us();
            uint32_t decrypt_time = (uint32_t)(decrypted - arrived);
            stats.decrypt_us += decrypt_time;
            if (decrypt_time > stats.max_decrypt_us) stats.max_decrypt_us = decrypt_time;
            length_prefixed_to_annexb((uint8_t *)frame, frame_len);
            int rc = video_decode(frame, frame_len);
            uint64_t decoded_at = now_us();
            uint32_t decode_time = (uint32_t)(decoded_at - decrypted);
            stats.decode_us += decode_time;
            if (decode_time > stats.max_decode_us) stats.max_decode_us = decode_time;
            if (rc != 0) {
                stats.failures++;
                if (++failures % 30 == 1 && s->callbacks.request_keyframe)
                    s->callbacks.request_keyframe(s->callbacks.ctx);
            } else {
                failures = 0;
            }
            stats_tick(&stats, decoded_at);
            break;
        }
        case OP_VIDEO_CONFIG:
            handle_config(body, size);
            break;
        default:
            break;
        }
    }
done:
    free(body);
    free(plain);
    vp_log("screen stream ended");
out:
    if (s->client_fd >= 0) close(s->client_fd);
    s->client_fd = -1;
    if (!s->stopping && s->callbacks.closed) s->callbacks.closed(s->callbacks.ctx);
    /* The context is never freed: screen_stop() may still be touching it. It is a few bytes per
     * stream, and the listening socket is closed by screen_stop(). */
    return NULL;
}

int screen_start(const uint8_t key[32], screen_callbacks callbacks) {
    screen_stop();
    screen_ctx *s = calloc(1, sizeof(*s));
    if (!s) return -1;
    memcpy(s->key, key, 32);
    s->callbacks = callbacks;
    s->client_fd = -1;
    s->listen_fd = tcp_listen(SCREEN_PORT);
    if (s->listen_fd < 0) {
        free(s);
        return -1;
    }
    current = s;
    spawn_thread(screen_thread, s);
    return SCREEN_PORT;
}

void screen_stop(void) {
    screen_ctx *s = current;
    current = NULL;
    if (!s) return;
    s->stopping = true;
    /* Unblock accept()/recv(); the thread closes the client socket itself. */
    shutdown(s->listen_fd, SHUT_RDWR);
    close(s->listen_fd);
    int client = s->client_fd;
    if (client >= 0) shutdown(client, SHUT_RDWR);
}

bool screen_active(void) { return current != NULL; }
