/*
 * iAP2 CSM builders — a C port of PlayPort's identification and wireless CarPlay handoff messages.
 *
 * CSM wire format (big-endian, no checksum):
 *   frame     = 0x4040 | u16 totalLen | u16 messageId | body
 *   parameter = u16 totalLen | u16 parameterId | payload       (totalLen includes the 4-byte header)
 *   group     = a parameter whose payload is itself a parameter list
 *   string    = UTF-8 + NUL      u16list = N*2 bytes      void = empty
 */
#include "iap2_ident.h"
#include <string.h>

typedef struct {
    unsigned char *b;
    int cap;
    int len;
    int ok;
} buf_t;

static void put_u16(buf_t *p, unsigned v) {
    if (p->len + 2 > p->cap) { p->ok = 0; return; }
    p->b[p->len++] = (unsigned char)(v >> 8);
    p->b[p->len++] = (unsigned char)v;
}

static void put_bytes(buf_t *p, const unsigned char *s, int n) {
    if (p->len + n > p->cap) { p->ok = 0; return; }
    memcpy(p->b + p->len, s, n);
    p->len += n;
}

/* Append one parameter: [len:2][id:2][payload]. */
static void param(buf_t *p, unsigned id, const unsigned char *pl, int n) {
    put_u16(p, 4 + n);
    put_u16(p, id);
    put_bytes(p, pl, n);
}

static void p_void(buf_t *p, unsigned id) { param(p, id, NULL, 0); }
static void p_u8(buf_t *p, unsigned id, unsigned v) {
    unsigned char x = (unsigned char)v;
    param(p, id, &x, 1);
}
static void p_u16(buf_t *p, unsigned id, unsigned v) {
    unsigned char x[2] = {(unsigned char)(v >> 8), (unsigned char)v};
    param(p, id, x, 2);
}
static void p_u32(buf_t *p, unsigned id, unsigned v) {
    unsigned char x[4] = {(unsigned char)(v >> 24), (unsigned char)(v >> 16),
                          (unsigned char)(v >> 8), (unsigned char)v};
    param(p, id, x, 4);
}
static void p_str(buf_t *p, unsigned id, const char *s) {
    int n = (int)strlen(s);
    put_u16(p, 4 + n + 1);
    put_u16(p, id);
    put_bytes(p, (const unsigned char *)s, n);
    unsigned char z = 0;
    put_bytes(p, &z, 1);
}
static void p_u16list(buf_t *p, unsigned id, const unsigned *vals, int count) {
    put_u16(p, 4 + count * 2);
    put_u16(p, id);
    for (int i = 0; i < count; i++) put_u16(p, vals[i]);
}
static void p_bytes(buf_t *p, unsigned id, const unsigned char *s, int n) { param(p, id, s, n); }

/* Write the 6-byte CSM frame header (0x4040, total length, message id) and return total. */
static int finish_frame(unsigned char *out, int body_len, unsigned msgid) {
    int total = 6 + body_len;
    out[0] = 0x40;
    out[1] = 0x40;
    out[2] = (unsigned char)(total >> 8);
    out[3] = (unsigned char)total;
    out[4] = (unsigned char)(msgid >> 8);
    out[5] = (unsigned char)msgid;
    return total;
}

/* Message lists the accessory advertises (wireless profile, no location/vehicle extras). */
static const unsigned SENT_MESSAGES[] = {
    0xaa01, 0xaa03, 0x5000, 0x5002, 0x5200, 0x5203, 0xae00, 0xae02,
    0x4157, 0x4159, 0x4154, 0x4156, 0x4301, /* (0xae03 PowerSourceUpdate dropped for wireless) */
    0x5703, /* AccessoryWiFiConfigurationInformation */
};
static const unsigned RECEIVED_MESSAGES[] = {
    0xaa00, 0xaa02, 0xaa04, 0xaa05, 0xea00, 0xea01, 0x5001, 0x5201, 0x5202,
    0xae01, 0x4158, 0x4155, 0x4300,
    0x4e0d, 0x4e0e, 0x5702, /* wireless phone messages */
};

int iap2_build_identification(unsigned char *out, int cap, const unsigned char mac6[6],
                              const char *name, const char *model, const char *manufacturer,
                              const char *serial, const char *fw, const char *hw,
                              const char *ea_protocol, const char *language, const char *ssid) {
    if (cap < 6 + 8) return -1;
    buf_t body = {out + 6, cap - 6, 0, 1}; /* reserve 6 bytes for the CSM frame header */

    p_str(&body, 0, name);
    p_str(&body, 1, model);
    p_str(&body, 2, manufacturer);
    p_str(&body, 3, serial);
    p_str(&body, 4, fw);
    p_str(&body, 5, hw);
    p_u16list(&body, 6, SENT_MESSAGES, (int)(sizeof(SENT_MESSAGES) / sizeof(SENT_MESSAGES[0])));
    p_u16list(&body, 7, RECEIVED_MESSAGES, (int)(sizeof(RECEIVED_MESSAGES) / sizeof(RECEIVED_MESSAGES[0])));
    p_u8(&body, 8, 0);   /* wireless: power-provided = 0 */
    p_u16(&body, 9, 20); /* MaximumCurrentDrawnFromDevice */

    /* group 10: SupportedExternalAccessoryProtocol { id=1, name, matchAction=0 } */
    {
        unsigned char g[128];
        buf_t gb = {g, sizeof(g), 0, 1};
        p_u8(&gb, 0, 1);
        p_str(&gb, 1, ea_protocol);
        p_u8(&gb, 2, 0);
        if (!gb.ok) return -1;
        p_bytes(&body, 10, g, gb.len);
    }

    p_str(&body, 12, language);
    /* param 13: current supported languages (string list); one language here. */
    {
        int n = (int)strlen(language);
        put_u16(&body, 4 + n + 1);
        put_u16(&body, 13);
        put_bytes(&body, (const unsigned char *)language, n);
        unsigned char z = 0;
        put_bytes(&body, &z, 1);
    }

    /* group 17: BluetoothTransportComponent { id=0, name, void, mac, name2, void } */
    {
        unsigned char g[64];
        buf_t gb = {g, sizeof(g), 0, 1};
        p_u16(&gb, 0, 0);
        p_str(&gb, 1, "blue");
        p_void(&gb, 2);
        p_bytes(&gb, 3, mac6, 6);
        p_str(&gb, 4, "blue");
        p_void(&gb, 5);
        if (!gb.ok) return -1;
        p_bytes(&body, 17, g, gb.len);
    }

    /* group 24: WirelessCarPlayTransportComponent { id=1, ssid, void, supportsWifi=1, void, void } */
    {
        unsigned char g[128];
        buf_t gb = {g, sizeof(g), 0, 1};
        p_u16(&gb, 0, 1);
        p_str(&gb, 1, ssid);
        p_void(&gb, 2);
        p_u16(&gb, 3, 1);
        p_void(&gb, 4);
        p_void(&gb, 5);
        if (!gb.ok) return -1;
        p_bytes(&body, 24, g, gb.len);
    }

    /* group 30: RouteGuidanceDisplayComponent { id=42, name, maxRoadNameLens, 8 } */
    {
        unsigned char g[64];
        buf_t gb = {g, sizeof(g), 0, 1};
        p_u16(&gb, 0, 42);
        p_str(&gb, 1, "RouteGuidance");
        p_u16(&gb, 2, 64);
        p_u16(&gb, 4, 64);
        p_u16(&gb, 6, 8);
        if (!gb.ok) return -1;
        p_bytes(&body, 30, g, gb.len);
    }

    if (!body.ok) return -1;
    return finish_frame(out, body.len, 0x1d01);
}

int iap2_build_bytes_msg(unsigned char *out, int cap, unsigned msgid,
                         const unsigned char *p0, int n) {
    int total = 6 + 4 + n;
    if (n < 0 || total > cap) return -1;
    out[0] = 0x40;
    out[1] = 0x40;
    out[2] = (unsigned char)(total >> 8);
    out[3] = (unsigned char)total;
    out[4] = (unsigned char)(msgid >> 8);
    out[5] = (unsigned char)msgid;
    out[6] = (unsigned char)((4 + n) >> 8); /* parameter length (incl 4-byte header) */
    out[7] = (unsigned char)(4 + n);
    out[8] = 0; /* parameter id 0 */
    out[9] = 0;
    memcpy(out + 10, p0, n);
    return total;
}

int iap2_get_param0(const unsigned char *f, int flen, const unsigned char **out) {
    if (flen < 10) return -1;
    int plen = (f[6] << 8) | f[7];
    int pid = (f[8] << 8) | f[9];
    if (pid != 0 || plen < 4 || 6 + plen > flen) return -1;
    *out = f + 10;
    return plen - 4;
}

int iap2_build_wifi_config(unsigned char *out, int cap, const char *ssid, const char *passphrase,
                           int security, int channel) {
    if (cap < 6 + 8) return -1;
    buf_t body = {out + 6, cap - 6, 0, 1};
    /* parameter 0 (BSSID) omitted: the Vita does not expose its own BSSID. */
    p_str(&body, 1, ssid);
    p_str(&body, 2, passphrase);
    p_u8(&body, 3, (unsigned)security);
    p_u8(&body, 4, (unsigned)channel);
    if (!body.ok) return -1;
    return finish_frame(out, body.len, 0x5703);
}

int iap2_build_carplay_start(unsigned char *out, int cap, const char *ssid, const char *passphrase,
                             int security, int channel, const char *ip, int airplay_port,
                             const char *device_id, const char *public_key,
                             const char *source_version) {
    if (cap < 6 + 8) return -1;
    buf_t body = {out + 6, cap - 6, 0, 1};

    /* group 1: wireless session { ssid, passphrase, u8 channel, ip, u8 security }. */
    {
        unsigned char g[256];
        buf_t gb = {g, sizeof(g), 0, 1};
        p_str(&gb, 0, ssid);
        p_str(&gb, 1, passphrase);
        p_u8(&gb, 2, (unsigned)channel);
        p_str(&gb, 3, ip);
        p_u8(&gb, 4, (unsigned)security);
        if (!gb.ok) return -1;
        p_bytes(&body, 1, g, gb.len);
    }
    p_u32(&body, 2, (unsigned)airplay_port);
    p_str(&body, 3, device_id);
    p_str(&body, 4, public_key);
    p_str(&body, 5, source_version);

    if (!body.ok) return -1;
    return finish_frame(out, body.len, 0x4301);
}

int iap2_build_subscription(unsigned char *out, int cap, int index) {
    if (cap < 6 + 8) return -1;
    buf_t body = {out + 6, cap - 6, 0, 1};
    unsigned msgid;
    switch (index) {
    case 0: { /* StartNowPlayingUpdates: two groups of requested property ids */
        msgid = 0x5000;
        unsigned char g[64];
        buf_t gb = {g, sizeof(g), 0, 1};
        p_void(&gb, 1); p_void(&gb, 4); p_void(&gb, 6); p_void(&gb, 12); p_void(&gb, 26);
        if (!gb.ok) return -1;
        p_bytes(&body, 0, g, gb.len);
        unsigned char g2[32];
        buf_t gb2 = {g2, sizeof(g2), 0, 1};
        p_void(&gb2, 0); p_void(&gb2, 1); p_void(&gb2, 7);
        if (!gb2.ok) return -1;
        p_bytes(&body, 1, g2, gb2.len);
        break;
    }
    case 1: /* StartRouteGuidanceUpdates */
        msgid = 0x5200;
        p_u16(&body, 0, 42); p_void(&body, 1); p_void(&body, 2);
        break;
    case 2: /* StartPowerUpdates */
        msgid = 0xae00;
        p_void(&body, 4); p_void(&body, 5); p_void(&body, 6);
        break;
    case 3: /* StartCommunicationsUpdates */
        msgid = 0x4157;
        p_void(&body, 0); p_void(&body, 4); p_void(&body, 5);
        break;
    case 4: /* StartCallStateUpdates */
        msgid = 0x4154;
        p_void(&body, 0); p_void(&body, 1); p_void(&body, 2);
        p_void(&body, 3); p_void(&body, 4); p_void(&body, 11);
        break;
    default:
        return -1;
    }
    if (!body.ok) return -1;
    return finish_frame(out, body.len, msgid);
}
