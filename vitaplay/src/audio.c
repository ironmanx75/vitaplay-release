/*
 * CarPlay audio streams (port of AudioStream.kt and the audio parts of CarPlayMediaEngine.kt).
 *
 * Each audio stream is RTP over UDP, one packet per datagram: a 12-byte RTP header, the
 * ChaCha20-Poly1305 ciphertext + 16-byte tag, then an 8-byte little-endian nonce. Header bytes
 * 4..11 (timestamp + SSRC) are the AEAD associated data. Payloads are big-endian LPCM, 48 kHz mono
 * Opus, or AAC-LC; every stream is decoded, resampled to 48 kHz stereo, and mixed into one
 * sceAudioOut port.
 *
 * AAC-LC is not decoded yet (it would need sceAudiodec); such a stream is accepted and logged so a
 * test shows whether the phone actually negotiates it. PCM and Opus play.
 */
#include "audio.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <opus/opus.h>
#include <psp2/audioout.h>

#include "crypto.h"

#define RTP_HEADER_LEN 12
#define NONCE_LEN 8
#define TAIL_LEN (AEAD_TAG + NONCE_LEN)
#define DATAGRAM_BYTES 4096
#define RING_FRAMES 48000 /* one second of 48 kHz stereo */
#define OUT_GRAIN 1024    /* sceAudioOut frames per write (~21 ms at 48 kHz) */

typedef enum { CODEC_LPCM, CODEC_OPUS, CODEC_AAC } codec_kind;

typedef struct {
    volatile bool active;
    int type;
    codec_kind codec;
    int src_rate;
    int src_channels;
    uint8_t key[32];
    int data_fd;
    int control_fd;
    OpusDecoder *opus;

    /* 48 kHz stereo ring buffer, written by the RX thread and drained by the output thread. */
    int16_t ring[RING_FRAMES * 2];
    volatile int head, tail, count; /* in frames */
    int lock;                       /* simple spin flag via __sync */

    /* Linear resampler carry (per channel), for non-48 kHz PCM. */
    int32_t phase; /* Q12 */
    int16_t last[2];

    unsigned packets;
} audio_stream;

static audio_stream g_streams[AUDIO_STREAM_COUNT];
static volatile bool g_output_running;

static audio_stream *stream_for(int type) {
    int idx = type - AUDIO_STREAM_FIRST;
    if (idx < 0 || idx >= AUDIO_STREAM_COUNT) return NULL;
    return &g_streams[idx];
}

/* ---- ring buffer (single writer, single reader; a tiny spinlock guards the indices) ---- */

static void ring_lock(audio_stream *s) {
    while (__sync_lock_test_and_set(&s->lock, 1)) { /* spin briefly */ }
}
static void ring_unlock(audio_stream *s) { __sync_lock_release(&s->lock); }

static void ring_push(audio_stream *s, const int16_t *frames, int n) {
    ring_lock(s);
    for (int i = 0; i < n; i++) {
        if (s->count == RING_FRAMES) { /* overflow: drop the oldest frame */
            s->tail = (s->tail + 1) % RING_FRAMES;
            s->count--;
        }
        s->ring[s->head * 2] = frames[i * 2];
        s->ring[s->head * 2 + 1] = frames[i * 2 + 1];
        s->head = (s->head + 1) % RING_FRAMES;
        s->count++;
    }
    ring_unlock(s);
}

/* Pops up to n stereo frames, adding them into acc (saturating). Missing frames stay as-is. */
static void ring_mix_into(audio_stream *s, int32_t *acc, int n) {
    ring_lock(s);
    int take = s->count < n ? s->count : n;
    for (int i = 0; i < take; i++) {
        acc[i * 2] += s->ring[s->tail * 2];
        acc[i * 2 + 1] += s->ring[s->tail * 2 + 1];
        s->tail = (s->tail + 1) % RING_FRAMES;
        s->count--;
    }
    ring_unlock(s);
}

/* ---- decode + resample ---- */

/* Push stereo frames at src_rate, linearly resampled to 48 kHz. */
static void resample_push(audio_stream *s, const int16_t *in, int n) {
    if (s->src_rate == 48000 || s->src_rate <= 0) {
        ring_push(s, in, n);
        return;
    }
    int32_t step = (int32_t)(((int64_t)s->src_rate << 12) / 48000); /* input frames per output, Q12 */
    int32_t phase = s->phase;
    int16_t out[2];
    for (;;) {
        int32_t ipos = phase >> 12;
        int32_t frac = phase & 0xfff;
        if (ipos >= n) break;
        for (int c = 0; c < 2; c++) {
            int16_t a = ipos < 0 ? s->last[c] : in[ipos * 2 + c];
            int16_t b = (ipos + 1) < n ? in[(ipos + 1) * 2 + c] : in[(n - 1) * 2 + c];
            out[c] = (int16_t)(a + (((int32_t)(b - a) * frac) >> 12));
        }
        ring_push(s, out, 1);
        phase += step;
    }
    s->phase = phase - (n << 12); /* carry the fractional remainder into the next packet */
    s->last[0] = in[(n - 1) * 2];
    s->last[1] = in[(n - 1) * 2 + 1];
}

static void decode_lpcm(audio_stream *s, const uint8_t *p, int len) {
    int ch = s->src_channels < 1 ? 1 : s->src_channels;
    int frames = len / (2 * ch);
    if (frames <= 0) return;
    int16_t stereo[DATAGRAM_BYTES]; /* >= frames*2; datagram caps the size */
    for (int i = 0; i < frames; i++) {
        int16_t l = (int16_t)((p[i * 2 * ch] << 8) | p[i * 2 * ch + 1]); /* big-endian */
        int16_t r = ch >= 2 ? (int16_t)((p[(i * 2 * ch) + 2] << 8) | p[(i * 2 * ch) + 3]) : l;
        stereo[i * 2] = l;
        stereo[i * 2 + 1] = r;
    }
    resample_push(s, stereo, frames);
}

static void decode_opus(audio_stream *s, const uint8_t *p, int len) {
    if (!s->opus) return;
    int16_t mono[5760]; /* up to 120 ms at 48 kHz */
    int n = opus_decode(s->opus, p, len, mono, 5760, 0);
    if (n <= 0) return;
    int16_t stereo[5760 * 2];
    for (int i = 0; i < n; i++) {
        stereo[i * 2] = mono[i];
        stereo[i * 2 + 1] = mono[i];
    }
    ring_push(s, stereo, n); /* Opus already decodes at 48 kHz */
}

/* ---- UDP receive ---- */

static void *audio_rx_thread(void *arg) {
    audio_stream *s = arg;
    uint8_t wire[DATAGRAM_BYTES];
    uint8_t plain[DATAGRAM_BYTES];
    while (s->active) {
        ssize_t n = recv(s->data_fd, wire, sizeof(wire), 0);
        if (n < 0) {
            if (s->active) continue;
            break;
        }
        if (n < RTP_HEADER_LEN + (int)TAIL_LEN) continue;
        const uint8_t *aad = wire + 4; /* 8 bytes: timestamp + SSRC */
        int sealed_len = (int)n - RTP_HEADER_LEN - NONCE_LEN;
        const uint8_t *sealed = wire + RTP_HEADER_LEN;
        const uint8_t *short_nonce = wire + n - NONCE_LEN;
        uint8_t nonce[12] = {0, 0, 0, 0};
        memcpy(nonce + 4, short_nonce, NONCE_LEN);
        if (chacha_open(plain, s->key, nonce, sealed, sealed_len, aad, 8) != 0) {
            if (s->packets == 0) vp_log("audio type=%d decrypt failed", s->type);
            continue;
        }
        int plen = sealed_len - AEAD_TAG;
        if (++s->packets <= 3)
            vp_log("audio type=%d packet %u codec=%d payload=%d", s->type, s->packets, s->codec, plen);
        switch (s->codec) {
        case CODEC_LPCM: decode_lpcm(s, plain, plen); break;
        case CODEC_OPUS: decode_opus(s, plain, plen); break;
        case CODEC_AAC:
            if (s->packets == 1) vp_log("audio type=%d is AAC-LC; not decoded yet (needs sceAudiodec)", s->type);
            break;
        }
    }
    return NULL;
}

/* ---- sceAudioOut playback: mixes every active stream into one port ---- */

static bool any_active(void) {
    for (int i = 0; i < AUDIO_STREAM_COUNT; i++)
        if (g_streams[i].active) return true;
    return false;
}

static void *audio_output_thread(void *arg) {
    (void)arg;
    int port = sceAudioOutOpenPort(SCE_AUDIO_OUT_PORT_TYPE_MAIN, OUT_GRAIN, AUDIO_RATE,
                                   SCE_AUDIO_OUT_MODE_STEREO);
    if (port < 0) {
        vp_log("sceAudioOutOpenPort failed (0x%08x); no audio output", (unsigned)port);
        g_output_running = false;
        return NULL;
    }
    vp_log("audio output port open (48 kHz stereo)");
    int16_t out[OUT_GRAIN * 2];
    int32_t acc[OUT_GRAIN * 2];
    while (g_output_running) {
        memset(acc, 0, sizeof(acc));
        for (int i = 0; i < AUDIO_STREAM_COUNT; i++)
            if (g_streams[i].active) ring_mix_into(&g_streams[i], acc, OUT_GRAIN);
        for (int i = 0; i < OUT_GRAIN * 2; i++) {
            int32_t v = acc[i];
            out[i] = (int16_t)(v > 32767 ? 32767 : v < -32768 ? -32768 : v);
        }
        sceAudioOutOutput(port, out); /* blocks, pacing the mixer at 48 kHz */
    }
    sceAudioOutReleasePort(port);
    return NULL;
}

/* Start the output thread the first time a stream is set up. */
static void ensure_output(void) {
    if (g_output_running) return;
    g_output_running = true;
    if (spawn_thread(audio_output_thread, NULL) != 0) {
        g_output_running = false;
        vp_log("could not start the audio output thread");
    }
}

/* ---- SETUP / teardown ---- */

/* audioFormat bit groups (see AudioStreamCodec.fromFormatBits). */
static void codec_from_format(uint64_t bits, const char *audio_type, codec_kind *codec, int *rate,
                              int *channels) {
    (void)audio_type;
    static const struct { uint64_t bit; int rate, ch; } pcm[] = {
        {0x4, 8000, 1},  {0x8, 8000, 2},   {0x10, 16000, 1}, {0x20, 16000, 2},
        {0x40, 24000, 1}, {0x80, 24000, 2}, {0x100, 32000, 1}, {0x200, 32000, 2},
        {0x400, 44100, 1}, {0x800, 44100, 2}, {0x4000, 48000, 1}, {0x8000, 48000, 2},
    };
    if (bits & (0x10000000ULL | 0x20000000ULL | 0x40000000ULL)) {
        *codec = CODEC_OPUS; *rate = 48000; *channels = 1; return;
    }
    if (bits & (0x400000ULL | 0x800000ULL)) {
        *codec = CODEC_AAC; *rate = (bits & 0x800000ULL) ? 48000 : 44100; *channels = 2; return;
    }
    for (size_t i = 0; i < sizeof(pcm) / sizeof(pcm[0]); i++)
        if (bits & pcm[i].bit) { *codec = CODEC_LPCM; *rate = pcm[i].rate; *channels = pcm[i].ch; return; }
    *codec = CODEC_LPCM; *rate = 44100; *channels = 2; /* default */
}

static int bind_udp_any(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0; /* ephemeral */
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    return fd;
}

static int local_port(int fd) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len) < 0) return -1;
    return ntohs(addr.sin_port);
}

pl_node *audio_stream_setup(int type, const pl_node *stream, const uint8_t key[32]) {
    audio_stream *s = stream_for(type);
    if (!s) return NULL;
    audio_stream_stop(type);

    uint64_t bits = 0;
    pl_get_u64(stream, "audioFormat", &bits);
    const char *audio_type = pl_get_str(stream, "audioType");
    codec_from_format(bits, audio_type, &s->codec, &s->src_rate, &s->src_channels);
    vp_log("SETUP audio type=%d audioType=%s codec=%d rate=%d ch=%d", type,
           audio_type[0] ? audio_type : "default", s->codec, s->src_rate, s->src_channels);

    s->data_fd = bind_udp_any();
    s->control_fd = bind_udp_any();
    if (s->data_fd < 0 || s->control_fd < 0) {
        if (s->data_fd >= 0) close(s->data_fd);
        if (s->control_fd >= 0) close(s->control_fd);
        return NULL;
    }
    if (s->codec == CODEC_OPUS) {
        int err = 0;
        s->opus = opus_decoder_create(48000, 1, &err);
        if (err != OPUS_OK || !s->opus) { vp_log("opus init failed (%d)", err); s->opus = NULL; }
    }
    memcpy(s->key, key, 32);
    s->type = type;
    s->head = s->tail = s->count = 0;
    s->phase = 0;
    s->last[0] = s->last[1] = 0;
    s->packets = 0;
    s->active = true;
    spawn_thread(audio_rx_thread, s);
    ensure_output();

    int data_port = local_port(s->data_fd);
    int control_port = local_port(s->control_fd);
    pl_node *r = pl_dict();
    pl_set(r, "type", pl_int(type));
    pl_set(r, "dataPort", pl_int(data_port));
    pl_set(r, "controlPort", pl_int(control_port));
    const pl_node *id = pl_get(stream, "streamConnectionID");
    if (id && id->type == PL_UINT) pl_set(r, "streamConnectionID", pl_uint(id->v.u));
    else if (id && id->type == PL_INT) pl_set(r, "streamConnectionID", pl_int(id->v.i));
    return r;
}

void audio_stream_stop(int type) {
    audio_stream *s = stream_for(type);
    if (!s || !s->active) return;
    s->active = false;
    if (s->data_fd >= 0) { shutdown(s->data_fd, SHUT_RDWR); close(s->data_fd); s->data_fd = -1; }
    if (s->control_fd >= 0) { close(s->control_fd); s->control_fd = -1; }
    if (s->opus) { opus_decoder_destroy(s->opus); s->opus = NULL; }
}

void audio_stop_all(void) {
    for (int i = 0; i < AUDIO_STREAM_COUNT; i++) audio_stream_stop(AUDIO_STREAM_FIRST + i);
}

pl_node *audio_feedback(void) {
    if (!any_active()) return NULL;
    pl_node *streams = pl_array();
    for (int i = 0; i < AUDIO_STREAM_COUNT; i++) {
        if (!g_streams[i].active) continue;
        pl_node *e = pl_dict();
        pl_set(e, "type", pl_int(g_streams[i].type));
        pl_push(streams, e);
    }
    pl_node *body = pl_dict();
    pl_set(body, "streams", streams);
    return body;
}

void audio_mix(int16_t *out, int frames) {
    int32_t acc[OUT_GRAIN * 2];
    int done = 0;
    while (done < frames) {
        int chunk = frames - done > OUT_GRAIN ? OUT_GRAIN : frames - done;
        memset(acc, 0, sizeof(int32_t) * chunk * 2);
        for (int i = 0; i < AUDIO_STREAM_COUNT; i++)
            if (g_streams[i].active) ring_mix_into(&g_streams[i], acc, chunk);
        for (int i = 0; i < chunk * 2; i++) {
            int32_t v = acc[i];
            out[(done * 2) + i] = (int16_t)(v > 32767 ? 32767 : v < -32768 ? -32768 : v);
        }
        done += chunk;
    }
}
