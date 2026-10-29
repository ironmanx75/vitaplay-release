#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <psp2/ctrl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/rtc.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/power.h>
#include <psp2/sysmodule.h>
#include <psp2/touch.h>
#include <vita2d.h>

#include "btboot.h"
#include "common.h"
#include "crypto.h"
#include "identity.h"
#include "mdns.h"
#include "mfi.h"
#include "session.h"
#include "video.h"
#include "wifi_setup.h"

int _newlib_heap_size_user = 128 * 1024 * 1024;

#define SCREEN_W 960
#define SCREEN_H 544
#define TOUCH_PANEL_W 1920
#define TOUCH_PANEL_H 1088

#define COLOR_BG RGBA8(0x12, 0x12, 0x16, 0xff)
#define COLOR_TEXT RGBA8(0xf0, 0xf0, 0xf0, 0xff)
#define COLOR_DIM RGBA8(0x90, 0x90, 0x98, 0xff)
#define COLOR_OK RGBA8(0x5c, 0xd6, 0x7a, 0xff)
#define COLOR_WARN RGBA8(0xff, 0xb3, 0x47, 0xff)
#define COLOR_PANEL RGBA8(0x00, 0x00, 0x00, 0xc0)

static vita2d_pgf *font;
static char net_memory[1024 * 1024];

static void parse_relay(vp_config *c, const char *value) {
    const char *colon = strchr(value, ':');
    size_t host_len = colon ? (size_t)(colon - value) : strlen(value);
    if (host_len == 0 || host_len >= sizeof(c->relay_host)) return;
    memcpy(c->relay_host, value, host_len);
    c->relay_host[host_len] = 0;
    c->relay_port = colon ? atoi(colon + 1) : 7140;
}

static void load_config(void) {
    vp_config *c = &g_config;
    snprintf(c->name, sizeof(c->name), "VitaPlay");
    snprintf(c->model, sizeof(c->model), "VitaPlay");
    snprintf(c->manufacturer, sizeof(c->manufacturer), "VitaPlay");
    snprintf(c->source_version, sizeof(c->source_version), "366.0");
    identity_device_id(c->device_id);
    snprintf(c->bt_mac, sizeof(c->bt_mac), "%s", c->device_id);
    c->width = SCREEN_W;
    c->height = SCREEN_H;
    c->fps = 60;
    c->night_mode = -1;
    c->wifi_ssid[0] = 0; /* auto-read from the network when left blank */
    c->wifi_pass[0] = 0;
    c->wifi_channel = 0;    /* 0 = let the phone scan for the SSID */
    c->wifi_security = 2;   /* WPA/WPA2 */

    /* Optional overrides: name=, bt_mac= (the Bluetooth bootstrap helper's address), fps=,
     * iap_relay=<ip>:<port> (PlayPort's --vita-bootstrap relay), night_mode=auto|day|night */
    FILE *f = fopen(APP_DIR "/config.txt", "r");
    if (!f) return;
    char line[160];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '#') continue;
        if (strncmp(line, "name=", 5) == 0) snprintf(c->name, sizeof(c->name), "%s", line + 5);
        else if (strncmp(line, "bt_mac=", 7) == 0) snprintf(c->bt_mac, sizeof(c->bt_mac), "%s", line + 7);
        else if (strncmp(line, "fps=", 4) == 0) c->fps = atoi(line + 4);
        else if (strncmp(line, "iap_relay=", 10) == 0) parse_relay(c, line + 10);
        else if (strncmp(line, "wifi_ssid=", 10) == 0) snprintf(c->wifi_ssid, sizeof(c->wifi_ssid), "%s", line + 10);
        else if (strncmp(line, "wifi_pass=", 10) == 0) snprintf(c->wifi_pass, sizeof(c->wifi_pass), "%s", line + 10);
        else if (strncmp(line, "wifi_channel=", 13) == 0) c->wifi_channel = atoi(line + 13);
        else if (strncmp(line, "wifi_security=", 14) == 0) c->wifi_security = atoi(line + 14);
        else if (strncmp(line, "night_mode=", 11) == 0) {
            const char *v = line + 11;
            c->night_mode = strcmp(v, "night") == 0 ? 1 : strcmp(v, "day") == 0 ? 0 : -1;
        }
    }
    fclose(f);
}

/* Everything the Bluetooth bootstrap helper must hand the iPhone to point it at this Vita. */
static void write_bootstrap_file(void) {
    FILE *f = fopen(APP_DIR "/bootstrap.txt", "w");
    if (!f) return;
    fprintf(f, "ip=%s\nairplay_port=%d\ndevice_id=%s\npublic_key=%s\nsource_version=%s\nname=%s\nbt_mac=%s\n",
            g_config.ip, AIRPLAY_PORT, g_config.device_id, g_identity.public_key_hex,
            g_config.source_version, g_config.name, g_config.bt_mac);
    fclose(f);
}

static void net_init(void) {
    sceSysmoduleLoadModule(SCE_SYSMODULE_NET);
    SceNetInitParam param = {net_memory, sizeof(net_memory), 0};
    sceNetInit(&param);
    sceNetCtlInit();
}

static bool get_ip(char out[16]) {
    SceNetCtlInfo info;
    if (sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_IP_ADDRESS, &info) < 0) return false;
    snprintf(out, 16, "%s", info.ip_address);
    return out[0] && strcmp(out, "0.0.0.0") != 0;
}

/* The SSID the Vita is joined to, for the wireless CarPlay handoff; config.txt can override it. */
static void fill_ssid(void) {
    if (g_config.wifi_ssid[0]) return; /* explicit wifi_ssid= wins */
    SceNetCtlInfo info;
    if (sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_SSID, &info) >= 0 && info.ssid[0])
        snprintf(g_config.wifi_ssid, sizeof(g_config.wifi_ssid), "%s", info.ssid);
}

static void draw_text(int x, int y, unsigned color, const char *fmt, ...) __attribute__((format(printf, 4, 5)));
static void draw_text(int x, int y, unsigned color, const char *fmt, ...) {
    char text[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(text, sizeof(text), fmt, args);
    va_end(args);
    vita2d_pgf_draw_text(font, x, y, color, 1.0f, text);
}

static const char *state_text(session_state state) {
    switch (state) {
    case SESSION_IDLE: return "Waiting for iPhone";
    case SESSION_CONNECTED: return "iPhone connected, pairing";
    case SESSION_VERIFIED: return "Paired, waiting for video";
    case SESSION_STREAMING: return "Streaming";
    }
    return "";
}

static void draw_status(session_state state, bool overlay) {
    if (overlay) vita2d_draw_rectangle(0, 0, SCREEN_W, SCREEN_H, COLOR_PANEL);
    int y = 40;
    draw_text(30, y, COLOR_TEXT, "VitaPlay - CarPlay receiver (wireless, experimental)");
    y += 40;
    draw_text(30, y, state == SESSION_IDLE ? COLOR_DIM : COLOR_OK, "Status: %s", state_text(state));
    y += 28;
    draw_text(30, y, COLOR_TEXT, "Vita IP: %s   AirPlay port: %d", g_config.ip, AIRPLAY_PORT);
    y += 28;
    draw_text(30, y, COLOR_TEXT, "Device ID: %s   BT ID: %s", g_config.device_id, g_config.bt_mac);
    y += 28;
    draw_text(30, y, mfi_ready() ? COLOR_OK : COLOR_WARN, "%s", mfi_status());
    y += 28;
    draw_text(30, y, g_config.wifi_pass[0] ? COLOR_OK : COLOR_WARN,
              "Wi-Fi: %s   Password: %s", g_config.wifi_ssid[0] ? g_config.wifi_ssid : "(auto-detect)",
              g_config.wifi_pass[0] ? "set" : "NOT SET");
    y += 28;
    if (state == SESSION_IDLE)
        draw_text(30, y, COLOR_DIM, "Square: set Wi-Fi network    Triangle: set Wi-Fi password");
    else
        draw_text(30, y, COLOR_DIM, "Set Wi-Fi from the home screen (before connecting)");
    y += 28;
    draw_text(30, y, COLOR_DIM, "Paired phones: %d   Setup code: 3939   Details: %s/bootstrap.txt",
              pairings_count(), APP_DIR);
    y += 28;
    draw_text(30, y, COLOR_DIM, "SELECT: toggle this panel   START+SELECT: quit");
    y += 28;
    draw_text(30, y, COLOR_DIM, "X/O/Triangle: select/back/home   Square: play/pause (in a call: answer/end)   START: Siri");
    y += 28;
    draw_text(30, y, COLOR_DIM, "D-pad: <- -> track, up/down night/day   Right stick: knob wheel   Left stick: knob nudge");

    char lines[10][96];
    int count = log_snapshot(lines, 10);
    y = SCREEN_H - 20 - (count - 1) * 22;
    for (int i = 0; i < count; i++, y += 22) draw_text(30, y, COLOR_DIM, "%s", lines[i]);
}

typedef struct {
    touch_contact contacts[TOUCH_CONTACTS];
} touch_frame;

/* A lifted finger keeps its last position: a release reported at (0,0) reads to iOS as a drag to
 * the corner, which cancels the tap, so buttons highlighted on press but never fired. */
static bool read_touch(touch_frame *out, const touch_frame *previous) {
    SceTouchData data;
    if (sceTouchPeek(SCE_TOUCH_PORT_FRONT, &data, 1) < 1) return false;
    for (unsigned i = 0; i < TOUCH_CONTACTS; i++) {
        out->contacts[i] = previous->contacts[i];
        out->contacts[i].down = false;
    }
    for (unsigned i = 0; i < data.reportNum && i < TOUCH_CONTACTS; i++) {
        out->contacts[i].down = true;
        out->contacts[i].x = data.report[i].x * g_config.width / TOUCH_PANEL_W;
        out->contacts[i].y = data.report[i].y * g_config.height / TOUCH_PANEL_H;
    }
    return true;
}

#define WHEEL_FIRST_REPEAT_US 400000
#define WHEEL_REPEAT_US 150000

static void read_knob(const SceCtrlData *pad, knob_state *k) {
    memset(k, 0, sizeof(*k));
    k->select = pad->buttons & SCE_CTRL_CROSS;
    k->back = pad->buttons & SCE_CTRL_CIRCLE;
    k->home = pad->buttons & SCE_CTRL_TRIANGLE;
    /* Knob nudges on the left stick (the D-pad is media and day/night): held past half travel. */
    int dx = (int)pad->lx - 128, dy = (int)pad->ly - 128;
    if (dx < -64) k->x = -1;
    if (dx > 64) k->x = 1;
    if (dy < -64) k->y = -1;
    if (dy > 64) k->y = 1;
}

/* Knob wheel on the right stick: up/left is -1 (previous item), down/right +1, 0 near the centre. */
static int right_stick_wheel(const SceCtrlData *pad) {
    int dx = (int)pad->rx - 128, dy = (int)pad->ry - 128;
    if (abs(dx) < 64 && abs(dy) < 64) return 0;
    int toward_start = abs(dy) >= abs(dx) ? dy < 0 : dx < 0;
    return toward_start ? -1 : 1;
}

/* Night between 19:00 and 07:00 local time; the Vita has no light sensor. */
static bool clock_says_night(void) {
    SceDateTime now;
    if (sceRtcGetCurrentClockLocalTime(&now) < 0) return false;
    return now.hour >= 19 || now.hour < 7;
}

static bool frame_wait(const char *message) {
    SceCtrlData pad;
    sceCtrlPeekBufferPositive(0, &pad, 1);
    vita2d_start_drawing();
    vita2d_clear_screen();
    draw_text(30, 40, COLOR_TEXT, "VitaPlay");
    draw_text(30, 90, COLOR_WARN, "%s", message);
    draw_text(30, 130, COLOR_DIM, "START: quit");
    vita2d_end_drawing();
    vita2d_swap_buffers();
    return !(pad.buttons & SCE_CTRL_START);
}

int main(void) {
    scePowerSetArmClockFrequency(444);
    scePowerSetBusClockFrequency(222);
    scePowerSetGpuClockFrequency(222);
    scePowerSetGpuXbarClockFrequency(166);

    sceIoMkdir(APP_DIR, 0777);
    sceIoMkdir(APP_DIR "/offline-mfi", 0777);
    log_init();
    vp_log("VitaPlay starting");

    vita2d_init();
    vita2d_set_clear_color(COLOR_BG);
    font = vita2d_load_default_pgf();
    sceCtrlSetSamplingMode(SCE_CTRL_MODE_ANALOG); /* both sticks drive the knob */
    sceTouchSetSamplingState(SCE_TOUCH_PORT_FRONT, SCE_TOUCH_SAMPLING_STATE_START);

    sceSysmoduleLoadModule(SCE_SYSMODULE_IME); /* on-screen keyboard for Wi-Fi setup */
    if (crypto_setup() != 0) vp_log("libsodium init failed");
    if (identity_load_or_create() != 0) vp_log("cannot write %s/identity.txt", APP_DIR);
    pairings_load();
    mfi_load();
    load_config();

    net_init();
    while (!get_ip(g_config.ip)) {
        if (!frame_wait("Waiting for Wi-Fi. Connect the Vita to the same network as the iPhone.")) goto quit;
    }
    vp_log("Wi-Fi up, IP %s", g_config.ip);
    fill_ssid();

    if (video_init(g_config.width, g_config.height) != 0) vp_log("video decoder unavailable");
    write_bootstrap_file();
    mdns_start();
    session_server_start();
    /* On-device Bluetooth iAP2 bootstrap: replaces the Mac bridge. Needs the kernel plugin loaded
     * at boot (see README); it waits quietly for the iPhone otherwise. */
    btboot_start();

    bool overlay = false;
    uint32_t last_buttons = 0;
    touch_frame last_touch = {0};
    knob_state last_knob = {0};
    bool start_alone = false; /* START went down without SELECT: a tap opens Siri */
    int night_override = g_config.night_mode; /* D-pad up/down replaces config/clock until VitaPlay restarts */
    uint64_t next_night_check = 0;
    int wheel_dir = 0;       /* right-stick wheel direction last frame */
    uint64_t wheel_next = 0; /* when a held stick turns the wheel again */

    for (;;) {
        /* Resets every idle timer (suspend, dimming, screen off) so the screen stays on. */
        sceKernelPowerTick(SCE_KERNEL_POWER_TICK_DEFAULT);
        SceCtrlData pad;
        sceCtrlPeekBufferPositive(0, &pad, 1);
        if ((pad.buttons & SCE_CTRL_START) && (pad.buttons & SCE_CTRL_SELECT)) break;
        uint32_t pressed = pad.buttons & ~last_buttons;
        uint32_t last_buttons_before = last_buttons;
        last_buttons = pad.buttons;
        uint32_t released = last_buttons_before & ~pad.buttons;
        if (pressed & SCE_CTRL_SELECT) overlay = !overlay;
        if (pressed & SCE_CTRL_START) start_alone = !(pad.buttons & SCE_CTRL_SELECT);
        if (pad.buttons & SCE_CTRL_SELECT) start_alone = false;

        /* Day/night: the D-pad override, else config, else the clock (checked once a minute). */
        uint64_t now = now_us();
        if (now >= next_night_check) {
            next_night_check = now + 60 * 1000000ULL;
            session_set_night_mode(night_override >= 0 ? night_override == 1 : clock_says_night());
        }

        session_state state = session_current_state();
        if (state == SESSION_STREAMING) {
            if (pressed & SCE_CTRL_SQUARE) {
                if (session_call_active()) session_send_telephony(TELEPHONY_HOOK_SWITCH);
                else session_send_media(MEDIA_PLAY_PAUSE);
            }
            if ((released & SCE_CTRL_START) && start_alone) {
                session_request_siri();
                start_alone = false;
            }
            if (pressed & SCE_CTRL_LEFT) session_send_media(MEDIA_PREVIOUS);
            if (pressed & SCE_CTRL_RIGHT) session_send_media(MEDIA_NEXT);
            if (pressed & (SCE_CTRL_UP | SCE_CTRL_DOWN)) {
                night_override = (pressed & SCE_CTRL_UP) ? 1 : 0;
                session_set_night_mode(night_override == 1);
            }
            touch_frame touch;
            if (read_touch(&touch, &last_touch) && memcmp(&touch, &last_touch, sizeof(touch)) != 0) {
                session_send_touch(touch.contacts);
                last_touch = touch;
            }
            knob_state knob;
            read_knob(&pad, &knob);
            /* The wheel is a relative axis: each report with +-1 is one detent. Holding the stick
             * repeats, after a pause, like a wheel turned steadily. */
            int dir = right_stick_wheel(&pad);
            bool wheel_step = false;
            if (dir != 0 && (dir != wheel_dir || now >= wheel_next)) {
                knob.wheel = dir;
                wheel_step = true;
                wheel_next = now + (dir != wheel_dir ? WHEEL_FIRST_REPEAT_US : WHEEL_REPEAT_US);
            }
            wheel_dir = dir;
            if (wheel_step || memcmp(&knob, &last_knob, sizeof(knob)) != 0) {
                session_send_knob(&knob);
                last_knob = knob;
            }
        } else {
            /* Not streaming: the face buttons set up Wi-Fi via the on-screen keyboard. */
            if (pressed & SCE_CTRL_SQUARE) {
                char ssid[33];
                if (wifi_prompt("Wi-Fi network name (SSID)", g_config.wifi_ssid, ssid, sizeof(ssid), false)) {
                    snprintf(g_config.wifi_ssid, sizeof(g_config.wifi_ssid), "%s", ssid);
                    wifi_save_config();
                }
                last_buttons = 0; /* the dialog consumed input; avoid a stale repeat */
            } else if (pressed & SCE_CTRL_TRIANGLE) {
                char pass[64];
                if (wifi_prompt("Wi-Fi password", g_config.wifi_pass, pass, sizeof(pass), true)) {
                    snprintf(g_config.wifi_pass, sizeof(g_config.wifi_pass), "%s", pass);
                    wifi_save_config();
                }
                last_buttons = 0;
            }
        }

        vita2d_start_drawing();
        vita2d_clear_screen();
        vita2d_texture *frame = video_front();
        if (state == SESSION_STREAMING && frame) {
            vita2d_draw_texture(frame, 0, 0);
            if (overlay) draw_status(state, true);
        } else {
            draw_status(state, false);
        }
        vita2d_end_drawing();
        vita2d_swap_buffers();
    }

quit:
    video_shutdown();
    vita2d_fini();
    sceKernelExitProcess(0);
    return 0;
}
