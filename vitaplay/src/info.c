#include "info.h"

#include "hid.h"

#define STREAM_TYPE_MAIN_SCREEN 110
#define DISPLAY_FEATURE_KNOBS 0x02
#define DISPLAY_FEATURE_HIGH_FIDELITY_TOUCH 0x08
/* CARPLAY_FEATURES already carries the audio feature bits; the no-audio variant masks them off.
 * Audio output is implemented (src/audio.c), so advertise the full set plus the audioFormats /
 * audioLatencies the phone needs to actually open an audio stream. */
#define CARPLAY_FEATURES 0x615653aee2LL

/* audioOutputFormats bitmasks (see AirPlayInfoPlist.audioFormats). We advertise EVERY PCM rate
 * (8/16/24/32/44.1/48 kHz, mono+stereo) so the phone always finds a PCM format it can send. */
#define AUDIO_PCM 0xcffc       /* LPCM, all rates, mono+stereo */
#define AUDIO_PCM_MONO 0x4554  /* LPCM, all rates, mono */
#define AUDIO_OPUS 0x70000000  /* 48 kHz Opus */
#define AUDIO_AAC_LC 0x800000  /* 48 kHz AAC-LC (stream 102 media) */
/* We advertise stream 102 media (AAC-LC) to match a real head unit exactly: some phones only route
 * media audio when AAC is offered. If the phone picks it, audio.c logs it (AAC decode is a TODO);
 * stream 100 media (PCM) is still offered, which we decode. The log shows which the phone opens. */

/* The PS Vita panel is 5 inches at 16:9. */
#define VITA_WIDTH_MM 110

static pl_node *resource(int id) {
    pl_node *r = pl_dict();
    pl_set(r, "resourceID", pl_int(id));
    pl_set(r, "transferType", pl_int(1));
    pl_set(r, "transferPriority", pl_int(100));
    pl_set(r, "takeConstraint", pl_int(100));
    pl_set(r, "borrowConstraint", pl_int(100));
    pl_set(r, "unborrowConstraint", pl_int(100));
    return r;
}

static pl_node *app_state(int id, const char *key, pl_node *value) {
    pl_node *s = pl_dict();
    pl_set(s, "appStateID", pl_int(id));
    pl_set(s, key, value);
    return s;
}

static pl_node *modes(void) {
    pl_node *m = pl_dict();
    pl_node *resources = pl_array();
    pl_push(resources, resource(1));
    pl_push(resources, resource(2));
    pl_set(m, "resources", resources);
    pl_node *states = pl_array();
    pl_push(states, app_state(2, "state", pl_bool(false)));
    pl_push(states, app_state(1, "speechMode", pl_int(-1)));
    pl_push(states, app_state(3, "state", pl_bool(false)));
    pl_set(m, "appStates", states);
    return m;
}

static pl_node *area(int width, int height) {
    pl_node *view = pl_dict();
    pl_set(view, "widthPixels", pl_int(width));
    pl_set(view, "heightPixels", pl_int(height));
    pl_set(view, "originXPixels", pl_int(0));
    pl_set(view, "originYPixels", pl_int(0));
    pl_node *safe = pl_dict();
    pl_set(safe, "widthPixels", pl_int(width));
    pl_set(safe, "heightPixels", pl_int(height));
    pl_set(safe, "originXPixels", pl_int(0));
    pl_set(safe, "originYPixels", pl_int(0));
    pl_set(safe, "drawUIOutsideSafeArea", pl_bool(true));
    pl_set(view, "safeArea", safe);
    return view;
}

static int sanitize_fps(int fps) {
    if (fps < 30) fps = 30;
    if (fps > 60) fps = 60;
    return ((fps - 30) + 2) / 5 * 5 + 30;
}

static pl_node *display(const vp_config *c) {
    int height_mm = (VITA_WIDTH_MM * c->height + c->width / 2) / c->width;
    pl_node *d = pl_dict();
    pl_set(d, "uuid", pl_str(MAIN_DISPLAY_UUID));
    pl_set(d, "type", pl_int(STREAM_TYPE_MAIN_SCREEN));
    pl_set(d, "maxFPS", pl_int(sanitize_fps(c->fps)));
    pl_set(d, "widthPixels", pl_int(c->width));
    pl_set(d, "heightPixels", pl_int(c->height));
    pl_set(d, "widthPhysical", pl_int(VITA_WIDTH_MM));
    pl_set(d, "heightPhysical", pl_int(height_mm));
    pl_set(d, "features", pl_int(DISPLAY_FEATURE_HIGH_FIDELITY_TOUCH | DISPLAY_FEATURE_KNOBS));
    pl_set(d, "primaryInputDevice", pl_int(1));
    /* Automatic UI/map appearance, declared before any setNightMode command (as DiPlay does). */
    pl_set(d, "uiAppearanceMode", pl_int(0));
    pl_set(d, "uiAppearanceSetting", pl_int(0));
    pl_set(d, "mapAppearanceMode", pl_int(0));
    pl_set(d, "mapAppearanceSetting", pl_int(0));
    pl_set(d, "viewAreas", pl_push(pl_array(), area(c->width, c->height)));
    pl_set(d, "initialViewArea", pl_int(0));
    return d;
}

/* One audioLatencies entry: {type, inputLatencyMicros:0, outputLatencyMicros:0, [audioType]}. */
static pl_node *latency(int type, const char *audio_type) {
    pl_node *e = pl_dict();
    pl_set(e, "type", pl_int(type));
    pl_set(e, "inputLatencyMicros", pl_int(0));
    pl_set(e, "outputLatencyMicros", pl_int(0));
    if (audio_type) pl_set(e, "audioType", pl_str(audio_type));
    return e;
}

static pl_node *audio_latencies(void) {
    pl_node *a = pl_array();
    pl_push(a, latency(100, NULL));
    pl_push(a, latency(100, "default"));
    pl_push(a, latency(100, "media"));
    pl_push(a, latency(100, "telephony"));
    pl_push(a, latency(100, "speechRecognition"));
    pl_push(a, latency(100, "alert"));
    pl_push(a, latency(101, NULL));
    pl_push(a, latency(101, "default"));
    pl_push(a, latency(102, "default"));
    return a;
}

/* One audioFormats entry: {type, audioType, audioOutputFormats}. (No microphone, so no input.) */
static pl_node *format(int type, const char *audio_type, int64_t output_formats) {
    pl_node *e = pl_dict();
    pl_set(e, "type", pl_int(type));
    pl_set(e, "audioType", pl_str(audio_type));
    pl_set(e, "audioOutputFormats", pl_int(output_formats));
    return e;
}

static pl_node *audio_formats(void) {
    pl_node *a = pl_array();
    pl_push(a, format(100, "compatibility", AUDIO_PCM));
    pl_push(a, format(101, "compatibility", AUDIO_PCM));
    pl_push(a, format(100, "default", AUDIO_PCM | AUDIO_OPUS));
    pl_push(a, format(100, "alert", AUDIO_PCM | AUDIO_OPUS));
    pl_push(a, format(100, "media", AUDIO_PCM));
    pl_push(a, format(100, "telephony", AUDIO_PCM_MONO | AUDIO_OPUS));
    pl_push(a, format(100, "speechRecognition", AUDIO_PCM_MONO | AUDIO_OPUS));
    pl_push(a, format(101, "default", AUDIO_PCM | AUDIO_OPUS));
    pl_push(a, format(102, "media", AUDIO_AAC_LC));
    return a;
}

pl_node *info_build(const vp_config *c) {
    pl_node *info = pl_dict();
    pl_set(info, "sourceVersion", pl_str(c->source_version));
    pl_set(info, "features", pl_int(CARPLAY_FEATURES));
    pl_set(info, "audioLatencies", audio_latencies());
    pl_set(info, "audioFormats", audio_formats());
    pl_set(info, "statusFlags", pl_int(4));
    pl_set(info, "model", pl_str(c->model));
    pl_set(info, "manufacturer", pl_str(c->manufacturer));
    pl_set(info, "deviceID", pl_str(c->device_id));
    pl_set(info, "bluetoothIDs", pl_push(pl_array(), pl_str(c->bt_mac)));
    pl_set(info, "name", pl_str(c->name));
    pl_set(info, "rightHandDrive", pl_bool(false));
    pl_set(info, "keepAliveLowPower", pl_bool(false));
    pl_set(info, "keepAliveSendStatsAsBody", pl_bool(false));
    pl_set(info, "modes", modes());

    pl_node *extended = pl_array();
    pl_push(extended, pl_str("vocoderInfo"));
    pl_push(extended, pl_str("enhancedRequestCarUI"));
    pl_set(info, "extendedFeatures", extended);
    pl_set(info, "displays", pl_push(pl_array(), display(c)));

    pl_node *hid = pl_array();
    pl_push(hid, hid_touch_device(c->width, c->height, MAIN_DISPLAY_UUID));
    pl_push(hid, hid_knob_device(MAIN_DISPLAY_UUID));
    pl_push(hid, hid_media_device(MAIN_DISPLAY_UUID));
    pl_push(hid, hid_telephony_device(MAIN_DISPLAY_UUID));
    pl_set(info, "hidDevices", hid);
    return info;
}
