/* Hardware H.264 decode (sceAvcdec) into vita2d textures. */
#pragma once

#include <vita2d.h>

#include "common.h"

/* Call on the main thread after vita2d_init(). */
int video_init(int width, int height);
void video_shutdown(void);

/* avcC record from the stream's VideoConfig message; SPS/PPS are sent before the next frame. */
void video_set_config(const uint8_t *avcc, size_t len);
/* Decodes one Annex B access unit. Returns -1 on a decoder error. */
int video_decode(const uint8_t *annexb, size_t len);
void video_reset(void);

/* Latest decoded frame, or NULL before the first one. */
vita2d_texture *video_front(void);
uint32_t video_frames_decoded(void);
