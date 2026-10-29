#include "video.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <psp2/kernel/sysmem.h>
#include <psp2/sysmodule.h>
#include <psp2/videodec.h>

#define TEXTURES 3
#define PTS_STEP 3000 /* 90 kHz ticks per frame at 30 fps */
#define ALIGN(x, a) (((x) + ((a) - 1)) & ~((a) - 1))

/* The decoder sizes its DPB from the stream's level, ignoring the VUI's max_dec_frame_buffering:
 * the iPhone sends High@3.1 at 960x544, so it wants 18000 / 2040 = 8 frames. With fewer it fails
 * with 0x80620003 (out of memory) whenever the DPB fills. sceVideodecInitLibrary rejects 10 and 16
 * with 0x80620802 (invalid param), so step down from 8. */
static const int ref_frame_choices[] = {8, 7, 6, 5};

static SceAvcdecCtrl decoder;
static SceUID decoder_block = -1;
static bool decoder_ready;
static vita2d_texture *textures[TEXTURES];
static volatile int front = -1;
static int back;
static int frame_width, frame_height;
static volatile uint32_t decoded;

static pthread_mutex_t config_lock = PTHREAD_MUTEX_INITIALIZER;
static buf_t parameter_sets; /* Annex B SPS + PPS */
static bool send_parameter_sets;
static buf_t au;

/* Initialises the library and creates the decoder with room for ref_frames; undoes itself on failure. */
static int create_decoder(int width, int height, int ref_frames) {
    SceVideodecQueryInitInfoHwAvcdec init = {0};
    init.size = sizeof(init);
    init.horizontal = ALIGN(width, 16);
    init.vertical = ALIGN(height, 16);
    init.numOfRefFrames = ref_frames;
    init.numOfStreams = 1;
    int rc = sceVideodecInitLibrary(SCE_VIDEODEC_TYPE_HW_AVCDEC, &init);
    if (rc < 0) {
        vp_log("sceVideodecInitLibrary (%d refs) failed 0x%08x", ref_frames, rc);
        return -1;
    }

    SceAvcdecQueryDecoderInfo query = {init.horizontal, init.vertical, init.numOfRefFrames};
    SceAvcdecDecoderInfo info = {0};
    rc = sceAvcdecQueryDecoderMemSize(SCE_VIDEODEC_TYPE_HW_AVCDEC, &query, &info);
    if (rc < 0) {
        vp_log("sceAvcdecQueryDecoderMemSize (%d refs) failed 0x%08x", ref_frames, rc);
        goto term;
    }
    /* The codec engine needs physically contiguous main memory; a CDRAM block is rejected by
     * sceAvcdecCreateDecoder with 0x80620009 (invalid pointer). */
    size_t size = ALIGN(info.frameMemSize, 1024 * 1024);
    decoder_block = sceKernelAllocMemBlock("vitaplay_avcdec", SCE_KERNEL_MEMBLOCK_TYPE_USER_MAIN_PHYCONT_NC_RW,
                                           size, NULL);
    if (decoder_block < 0) {
        vp_log("decoder memory alloc (%d refs, %u bytes, phycont) failed 0x%08x", ref_frames,
               (unsigned)size, decoder_block);
        goto term;
    }
    memset(&decoder, 0, sizeof(decoder));
    sceKernelGetMemBlockBase(decoder_block, &decoder.frameBuf.pBuf);
    decoder.frameBuf.size = size;
    rc = sceAvcdecCreateDecoder(SCE_VIDEODEC_TYPE_HW_AVCDEC, &decoder, &query);
    if (rc < 0) {
        vp_log("sceAvcdecCreateDecoder (%d refs) failed 0x%08x", ref_frames, rc);
        sceKernelFreeMemBlock(decoder_block);
        decoder_block = -1;
        goto term;
    }
    vp_log("H.264 decoder created with %d reference frames (%u KB)", ref_frames, (unsigned)(size / 1024));
    return 0;
term:
    sceVideodecTermLibrary(SCE_VIDEODEC_TYPE_HW_AVCDEC);
    return -1;
}

int video_init(int width, int height) {
    frame_width = width;
    frame_height = height;
    /* Apps get SceVideodec from their imports; on retail firmware this sysmodule id is rejected
     * with 0x805a1000 (invalid value), so a failure here is not fatal. */
    int rc = sceSysmoduleLoadModule(SCE_SYSMODULE_AVCDEC);
    if (rc < 0) vp_log("AVCDEC sysmodule not loaded (0x%08x); continuing with the imported decoder", rc);

    int created = -1;
    for (size_t i = 0; i < sizeof(ref_frame_choices) / sizeof(ref_frame_choices[0]) && created != 0; i++)
        created = create_decoder(width, height, ref_frame_choices[i]);
    if (created != 0) return -1;

    for (int i = 0; i < TEXTURES; i++) {
        textures[i] = vita2d_create_empty_texture_format(width, height,
                                                         SCE_GXM_TEXTURE_FORMAT_U8U8U8U8_ABGR);
        if (!textures[i]) {
            vp_log("video texture alloc failed");
            return -1;
        }
    }
    decoder_ready = true;
    vp_log("H.264 decoder ready %dx%d", width, height);
    return 0;
}

void video_shutdown(void) {
    if (decoder_ready) sceAvcdecDeleteDecoder(&decoder);
    if (decoder_block >= 0) sceKernelFreeMemBlock(decoder_block);
    sceVideodecTermLibrary(SCE_VIDEODEC_TYPE_HW_AVCDEC);
    decoder_ready = false;
}

void video_set_config(const uint8_t *avcc, size_t len) {
    static const uint8_t start_code[4] = {0, 0, 0, 1};
    buf_t sets = {0};
    if (len >= 7) {
        size_t pos = 5;
        int sps_count = avcc[pos++] & 0x1f;
        for (int i = 0; i < sps_count && pos + 2 <= len; i++) {
            size_t n = get_u16be(avcc + pos);
            pos += 2;
            if (pos + n > len) break;
            buf_append(&sets, start_code, 4);
            buf_append(&sets, avcc + pos, n);
            pos += n;
        }
        int pps_count = pos < len ? avcc[pos++] : 0;
        for (int i = 0; i < pps_count && pos + 2 <= len; i++) {
            size_t n = get_u16be(avcc + pos);
            pos += 2;
            if (pos + n > len) break;
            buf_append(&sets, start_code, 4);
            buf_append(&sets, avcc + pos, n);
            pos += n;
        }
    }
    pthread_mutex_lock(&config_lock);
    /* The phone resends its config with every keyframe; only log when it actually changes. */
    bool changed = sets.len != parameter_sets.len ||
                   (sets.len && memcmp(sets.data, parameter_sets.data, sets.len) != 0);
    buf_free(&parameter_sets);
    parameter_sets = sets;
    send_parameter_sets = sets.len > 0;
    pthread_mutex_unlock(&config_lock);
    if (changed) vp_log("video config: %u bytes of SPS/PPS", (unsigned)sets.len);
}

int video_decode(const uint8_t *annexb, size_t len) {
    if (!decoder_ready) return -1;
    buf_clear(&au);
    pthread_mutex_lock(&config_lock);
    if (send_parameter_sets) {
        buf_append(&au, parameter_sets.data, parameter_sets.len);
        send_parameter_sets = false;
    }
    pthread_mutex_unlock(&config_lock);
    buf_append(&au, annexb, len);

    /* Real, increasing timestamps are required: with pts/dts "unknown" (0xffffffff) the decoder held
     * ~11 frames before its first output and then overflowed with 0x80620003 (out of memory).
     * It accepts one output picture per call; numOfElm > 1 fails with 0x80620002 (invalid param). */
    static uint64_t pts;
    pts += PTS_STEP;
    SceAvcdecAu unit = {0};
    unit.pts.upper = unit.dts.upper = (uint32_t)(pts >> 32);
    unit.pts.lower = unit.dts.lower = (uint32_t)pts;
    unit.es.pBuf = au.data;
    unit.es.size = au.len;

    vita2d_texture *target = textures[back];
    SceAvcdecPicture picture = {0};
    picture.size = sizeof(picture);
    picture.frame.pixelType = SCE_AVCDEC_PIXELFORMAT_RGBA8888;
    picture.frame.framePitch = vita2d_texture_get_stride(target) / 4;
    picture.frame.frameWidth = frame_width;
    picture.frame.frameHeight = frame_height;
    picture.frame.pPicture[0] = vita2d_texture_get_datap(target);

    SceAvcdecPicture *pictures[1] = {&picture};
    SceAvcdecArrayPicture array = {0};
    array.numOfElm = 1;
    array.pPicture = pictures;

    int rc = sceAvcdecDecode(&decoder, &unit, &array);
    if (rc < 0) {
        vp_log("sceAvcdecDecode failed 0x%08x", rc);
        return -1;
    }
    if (array.numOfOutput > 0) {
        if (decoded == 0)
            vp_log("first picture: %ux%u", (unsigned)picture.frame.horizontalSize,
                   (unsigned)picture.frame.verticalSize);
        front = back;
        back = (back + 1) % TEXTURES;
        decoded++;
    }
    return 0;
}

void video_reset(void) {
    front = -1;
    decoded = 0;
}

vita2d_texture *video_front(void) {
    int index = front;
    return index >= 0 ? textures[index] : NULL;
}

uint32_t video_frames_decoded(void) { return decoded; }
