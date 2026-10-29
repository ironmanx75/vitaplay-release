/*
 * CarPlay audio streams (port of AudioStream.kt and the audio parts of CarPlayMediaEngine.kt).
 *
 * Each stream is RTP over UDP, one packet per datagram: a 12-byte RTP header, ChaCha20-Poly1305
 * ciphertext and tag, then an 8-byte nonce. The RTP timestamp and SSRC (header bytes 4..11) are
 * the AAD. Payloads are big-endian LPCM or 48 kHz mono Opus; every stream is resampled to
 * 48 kHz stereo, buffered, and mixed for one output port.
 */
#pragma once

#include "bplist.h"
#include "common.h"

#define AUDIO_RATE 48000
#define AUDIO_STREAM_FIRST 100 /* main audio */
#define AUDIO_STREAM_COUNT 3   /* 100 main, 101 alt, 102 main high */

/* Starts a stream from its SETUP dictionary. Returns the SETUP response entry, or NULL to reject. */
pl_node *audio_stream_setup(int type, const pl_node *stream, const uint8_t key[32]);
void audio_stream_stop(int type);
void audio_stop_all(void);

/* /feedback body ({"streams": [...]}) for the active streams, or NULL when none is active. */
pl_node *audio_feedback(void);

/* Fills frames of interleaved 48 kHz stereo, mixing every active stream. Silence when idle. */
void audio_mix(int16_t *out, int frames);
