/*
 * On-device Bluetooth iAP2 bootstrap driver. See btboot.h.
 *
 * Ported from the l2capprobe test app's iAP2 driver loop, with the Wi-Fi/CarPlay handoff
 * (0x5703 AccessoryWiFiConfigurationInformation, 0x4301 CarPlayStartSession) added so the phone is
 * sent to this Vita's own AirPlay receiver instead of the Mac bridge's.
 */
#include "btboot.h"

#include <stdio.h>
#include <string.h>

#include <psp2/kernel/threadmgr.h>

#include "common.h"
#include "iap2_ident.h"
#include "identity.h"
#include "mfi.h"
#include "iap2_link.h"

/* VitaPlayBt pipe syscalls exported by the kernel plugin (linked via its weak stub, so these
 * degrade to safe no-ops when the plugin is not resident). */
extern int vpbt_status(void);
extern int vpbt_read(void *buf, int max);
extern int vpbt_write(const void *buf, int len);

static int64_t now_ms(void) { return (int64_t)(now_us() / 1000); }

/* "02:AB:CD:EF:01:23" -> 6 bytes; leaves a placeholder on a malformed id. */
static void parse_mac(const char *s, unsigned char out[6]) {
    static const unsigned char fallback[6] = {0x00, 0x25, 0x00, 0xAA, 0xBB, 0xCC};
    memcpy(out, fallback, 6);
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) == 6)
        for (int i = 0; i < 6; i++) out[i] = (unsigned char)v[i];
}

static const char *statename(iap2_link_state s) {
    switch (s) {
    case IAP2_LINK_IDLE: return "IDLE";
    case IAP2_LINK_DETECTING: return "DETECTING";
    case IAP2_LINK_NEGOTIATING: return "NEGOTIATING";
    case IAP2_LINK_NORMAL: return "NORMAL";
    case IAP2_LINK_DEAD: return "DEAD";
    default: return "?";
    }
}

/* Send the Wi-Fi configuration (0x5703): the network the phone should join for wireless CarPlay. */
static void send_wifi_config(iap2_link *link) {
    unsigned char msg[256];
    int n = iap2_build_wifi_config(msg, sizeof(msg), g_config.wifi_ssid, g_config.wifi_pass,
                                   g_config.wifi_security, g_config.wifi_channel);
    if (n > 0 && iap2_link_send_control(link, msg, (size_t)n, now_ms()) == 0)
        vp_log("iap2 tx=0x5703 wifi-config ssid=%s", g_config.wifi_ssid);
    else
        vp_log("iap2 0x5703 build/send failed (%d)", n);
}

/* Send CarPlayStartSession (0x4301): points the phone at this receiver's address and identity. */
static void send_carplay_start(iap2_link *link) {
    unsigned char msg[512];
    int n = iap2_build_carplay_start(msg, sizeof(msg), g_config.wifi_ssid, g_config.wifi_pass,
                                     g_config.wifi_security, g_config.wifi_channel, g_config.ip,
                                     AIRPLAY_PORT, g_config.device_id, g_identity.public_key_hex,
                                     g_config.source_version);
    if (n > 0 && iap2_link_send_control(link, msg, (size_t)n, now_ms()) == 0)
        vp_log("iap2 tx=0x4301 carplay-start ip=%s port=%d", g_config.ip, AIRPLAY_PORT);
    else
        vp_log("iap2 0x4301 build/send failed (%d)", n);
}

static void handle_control(iap2_link *link, const unsigned char *data, size_t len,
                           const unsigned char mac6[6], const char *serial, int *ident_sent) {
    unsigned msgid = len >= 6 ? ((data[4] << 8) | data[5]) : 0;
    switch (msgid) {
    case 0x1d00: /* StartIdentification -> send IdentificationInformation */
        if (!*ident_sent) {
            unsigned char idmsg[768];
            int idn = iap2_build_identification(idmsg, sizeof(idmsg), mac6, g_config.name,
                                                g_config.model, g_config.manufacturer, serial,
                                                "1.0.0", "1.0", "com.shilapi.xcertplay", "en",
                                                g_config.wifi_ssid);
            if (idn > 0) {
                iap2_link_send_control(link, idmsg, (size_t)idn, now_ms());
                *ident_sent = 1;
                vp_log("iap2 tx=0x1d01 identification (%d bytes)", idn);
            } else {
                vp_log("iap2 identification build failed (%d)", idn);
            }
        }
        break;
    case 0x1d02: vp_log("iap2 identification accepted (0x1d02)"); break;
    case 0x1d03: vp_log("iap2 identification REJECTED (0x1d03)"); break;
    case 0xaa00: { /* RequestAuthenticationCertificate -> send our MFi certificate */
        size_t cn = 0;
        const unsigned char *cert = mfi_cert(&cn);
        if (cert && cn > 0) {
            unsigned char m[2048];
            int mn = iap2_build_bytes_msg(m, sizeof(m), 0xaa01, cert, (int)cn);
            if (mn > 0) {
                iap2_link_send_control(link, m, (size_t)mn, now_ms());
                vp_log("iap2 tx=0xaa01 certificate (%u bytes)", (unsigned)cn);
            } else {
                vp_log("iap2 0xaa01 build failed (cert %u too big)", (unsigned)cn);
            }
        } else {
            vp_log("iap2 0xaa00 but MFi not ready (%s)", mfi_status());
        }
        break;
    }
    case 0xaa02: { /* RequestChallengeResponse -> sign the 32-byte digest */
        const unsigned char *chal = NULL;
        int cl = iap2_get_param0(data, (int)len, &chal);
        if (cl == 32) {
            unsigned char sig[64];
            if (mfi_sign_digest(chal, sig) == 0) {
                unsigned char m[128];
                int mn = iap2_build_bytes_msg(m, sizeof(m), 0xaa03, sig, 64);
                iap2_link_send_control(link, m, (size_t)mn, now_ms());
                vp_log("iap2 tx=0xaa03 response (sig 64)");
            } else {
                vp_log("iap2 MFi sign failed");
            }
        } else {
            vp_log("iap2 0xaa02 bad challenge len=%d", cl);
        }
        break;
    }
    case 0xaa05: vp_log("iap2 *** MFi AUTHENTICATION SUCCEEDED (0xaa05) ***"); break;
    case 0xaa04: vp_log("iap2 MFi AUTHENTICATION FAILED (0xaa04)"); break;
    case 0x5702: /* RequestAccessoryWiFiConfigurationInformation */
        vp_log("iap2 rx=0x5702 request-wifi-configuration");
        send_wifi_config(link);
        break;
    case 0x4300: /* CarPlayAvailability -> start the session on this receiver */
        vp_log("iap2 rx=0x4300 carplay-availability");
        send_carplay_start(link);
        break;
    case 0x4e0d: vp_log("iap2 rx=0x4e0d wireless-carplay-update"); break;
    case 0x4e0e: /* DeviceTransportIdentifier -> resend the Wi-Fi configuration */
        vp_log("iap2 rx=0x4e0e device-transport-identifier; resending 0x5703");
        send_wifi_config(link);
        break;
    default: break;
    }
}

static void *btboot_thread(void *arg) {
    (void)arg;
    unsigned char mac6[6];
    parse_mac(g_config.device_id, mac6);
    char serial[40];
    snprintf(serial, sizeof(serial), "CARPLAYWEB-%02X%02X%02X%02X%02X%02X", mac6[0], mac6[1],
             mac6[2], mac6[3], mac6[4], mac6[5]);

    iap2_link *link = NULL;
    iap2_link_state last_state = IAP2_LINK_IDLE;
    int ident_sent = 0;
    int logged_wait = 0;

    for (;;) {
        int up = vpbt_status();
        if (up == 1 && !link) {
            iap2_link_config cfg;
            iap2_link_config_wireless(&cfg);
            link = iap2_link_new(&cfg);
            if (link) {
                iap2_link_start(link, false, now_ms()); /* accessory: the iPhone initiates sync */
                last_state = iap2_link_get_state(link);
                ident_sent = 0;
                vp_log("iap2 bootstrap: pipe up, link started");
            }
        } else if (up != 1 && link) {
            iap2_link_free(link);
            link = NULL;
            vp_log("iap2 bootstrap: pipe down (%d), link freed", up);
        } else if (up != 1 && !logged_wait) {
            vp_log("iap2 bootstrap: waiting for the iPhone (plugin resident=%d)", up);
            logged_wait = 1;
        }

        if (link) {
            int64_t t = now_ms();
            unsigned char buf[512];
            int got;
            while ((got = vpbt_read(buf, sizeof(buf))) > 0)
                iap2_link_feed(link, buf, (size_t)got, t);
            int64_t dl = iap2_link_next_deadline(link);
            if (dl >= 0 && t >= dl) iap2_link_advance(link, t);
            unsigned char out[512];
            size_t n;
            while ((n = iap2_link_output(link, out, sizeof(out))) > 0)
                vpbt_write(out, (int)n);
            iap2_link_event ev;
            while (iap2_link_poll_event(link, &ev)) {
                if (ev.type == IAP2_LINK_EVENT_CONTROL)
                    handle_control(link, ev.data, ev.len, mac6, serial, &ident_sent);
                else if (ev.type == IAP2_LINK_EVENT_DEAD)
                    vp_log("iap2 bootstrap: link dead (%s)", ev.reason ? ev.reason : "eof");
            }
            iap2_link_state s = iap2_link_get_state(link);
            if (s != last_state) {
                vp_log("iap2 bootstrap: %s -> %s", statename(last_state), statename(s));
                last_state = s;
            }
        }
        sceKernelDelayThread(5000); /* 5 ms: responsive without busy-spinning */
    }
    return NULL;
}

void btboot_start(void) {
    if (spawn_thread(btboot_thread, NULL) != 0)
        vp_log("iap2 bootstrap: could not start thread");
}
