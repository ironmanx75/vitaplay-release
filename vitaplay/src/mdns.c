#include "mdns.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "identity.h"

#define MDNS_PORT 5353
#define MDNS_GROUP "224.0.0.251"
#define SERVICE_TYPE "_airplay._tcp.local"
#define SERVICES_META "_services._dns-sd._udp.local"

#define TYPE_A 1
#define TYPE_PTR 12
#define TYPE_TXT 16
#define TYPE_SRV 33
#define TYPE_ANY 255
#define CLASS_IN 1
#define CACHE_FLUSH 0x8000

static int sock = -1;
static char host_label[32];
static char instance_lower[96]; /* "<name>._airplay._tcp.local", lowercase */
static char host_lower[64];     /* "<host>.local", lowercase */

static void put_u16(buf_t *b, uint16_t v) {
    uint8_t p[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    buf_append(b, p, 2);
}

static void put_u32(buf_t *b, uint32_t v) {
    uint8_t p[4];
    put_u32be(p, v);
    buf_append(b, p, 4);
}

static void put_label(buf_t *b, const char *label, size_t len) {
    uint8_t n = (uint8_t)(len > 63 ? 63 : len);
    buf_append(b, &n, 1);
    buf_append(b, label, n);
}

static void put_dotted(buf_t *b, const char *name) {
    while (*name) {
        const char *dot = strchr(name, '.');
        size_t len = dot ? (size_t)(dot - name) : strlen(name);
        put_label(b, name, len);
        name += len + (dot ? 1 : 0);
    }
    uint8_t zero = 0;
    buf_append(b, &zero, 1);
}

static void put_instance(buf_t *b) {
    put_label(b, g_config.name, strlen(g_config.name));
    put_dotted(b, SERVICE_TYPE);
}

static void put_host(buf_t *b) {
    put_label(b, host_label, strlen(host_label));
    put_dotted(b, "local");
}

/* Writes type/class/ttl and returns the rdlength offset to patch. */
static size_t record_header(buf_t *b, uint16_t type, uint16_t klass, uint32_t ttl) {
    put_u16(b, type);
    put_u16(b, klass);
    put_u32(b, ttl);
    size_t at = b->len;
    put_u16(b, 0);
    return at;
}

static void patch_rdlength(buf_t *b, size_t at) {
    size_t len = b->len - at - 2;
    b->data[at] = (uint8_t)(len >> 8);
    b->data[at + 1] = (uint8_t)len;
}

static void put_txt(buf_t *b, const char *key, const char *value) {
    char entry[256];
    int n = snprintf(entry, sizeof(entry), "%s=%s", key, value);
    uint8_t len = (uint8_t)(n > 255 ? 255 : n); /* TXT strings allow 255 bytes, unlike labels */
    buf_append(b, &len, 1);
    buf_append(b, entry, len);
}

static void build_response(buf_t *b, uint16_t id) {
    put_u16(b, id);
    put_u16(b, 0x8400); /* response, authoritative */
    put_u16(b, 0);
    put_u16(b, 5);
    put_u16(b, 0);
    put_u16(b, 0);

    size_t at;
    put_dotted(b, SERVICES_META);
    at = record_header(b, TYPE_PTR, CLASS_IN, 4500);
    put_dotted(b, SERVICE_TYPE);
    patch_rdlength(b, at);

    put_dotted(b, SERVICE_TYPE);
    at = record_header(b, TYPE_PTR, CLASS_IN, 4500);
    put_instance(b);
    patch_rdlength(b, at);

    put_instance(b);
    at = record_header(b, TYPE_SRV, CLASS_IN | CACHE_FLUSH, 120);
    put_u16(b, 0);
    put_u16(b, 0);
    put_u16(b, AIRPLAY_PORT);
    put_host(b);
    patch_rdlength(b, at);

    put_instance(b);
    at = record_header(b, TYPE_TXT, CLASS_IN | CACHE_FLUSH, 4500);
    put_txt(b, "deviceid", g_config.device_id);
    put_txt(b, "features", "0x44540380,0x61");
    put_txt(b, "flags", "0x4");
    put_txt(b, "model", g_config.model);
    put_txt(b, "srcvers", g_config.source_version);
    put_txt(b, "protovers", "1.1");
    put_txt(b, "pi", g_identity.pairing_id);
    put_txt(b, "pk", g_identity.public_key_hex);
    patch_rdlength(b, at);

    put_host(b);
    at = record_header(b, TYPE_A, CLASS_IN | CACHE_FLUSH, 120);
    struct in_addr ip;
    inet_aton(g_config.ip, &ip);
    buf_append(b, &ip.s_addr, 4);
    patch_rdlength(b, at);
}

static void send_response(const struct sockaddr_in *to, uint16_t id) {
    buf_t packet = {0};
    build_response(&packet, id);
    sendto(sock, packet.data, packet.len, 0, (const struct sockaddr *)to, sizeof(*to));
    buf_free(&packet);
}

static void announce(void) {
    struct sockaddr_in group = {0};
    group.sin_family = AF_INET;
    group.sin_port = htons(MDNS_PORT);
    group.sin_addr.s_addr = inet_addr(MDNS_GROUP);
    send_response(&group, 0);
}

/* Reads a possibly compressed name as lowercase dotted text. */
static bool read_name(const uint8_t *p, size_t len, size_t *pos, char *out, size_t max) {
    size_t at = *pos, written = 0;
    bool jumped = false;
    for (int hops = 0; hops < 32; hops++) {
        if (at >= len) return false;
        uint8_t n = p[at];
        if (n == 0) {
            if (!jumped) *pos = at + 1;
            if (written && out[written - 1] == '.') written--;
            out[written] = 0;
            return true;
        }
        if ((n & 0xc0) == 0xc0) {
            if (at + 1 >= len) return false;
            if (!jumped) *pos = at + 2;
            at = ((n & 0x3f) << 8) | p[at + 1];
            jumped = true;
            continue;
        }
        if (at + 1 + n > len || written + n + 1 >= max) return false;
        for (int i = 0; i < n; i++) out[written++] = (char)tolower(p[at + 1 + i]);
        out[written++] = '.';
        at += 1 + n;
    }
    return false;
}

static bool question_matches(const char *name, uint16_t type) {
    if (strcmp(name, SERVICE_TYPE) == 0 || strcmp(name, SERVICES_META) == 0)
        return type == TYPE_PTR || type == TYPE_ANY;
    if (strcmp(name, instance_lower) == 0) return type == TYPE_SRV || type == TYPE_TXT || type == TYPE_ANY;
    if (strcmp(name, host_lower) == 0) return type == TYPE_A || type == TYPE_ANY;
    return false;
}

static void *mdns_thread(void *arg) {
    (void)arg;
    uint8_t packet[1500];
    for (;;) {
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int n = recvfrom(sock, packet, sizeof(packet), 0, (struct sockaddr *)&from, &from_len);
        if (n < 12) {
            if (n < 0) usleep(100 * 1000);
            continue;
        }
        if (packet[2] & 0x80) continue; /* a response, possibly our own */
        uint16_t questions = get_u16be(packet + 4);
        size_t pos = 12;
        bool match = false;
        for (int q = 0; q < questions && !match; q++) {
            char name[256];
            if (!read_name(packet, n, &pos, name, sizeof(name)) || pos + 4 > (size_t)n) break;
            uint16_t type = get_u16be(packet + pos);
            pos += 4;
            match = question_matches(name, type);
        }
        if (!match) continue;
        announce();
        /* Legacy one-shot resolvers query from an ephemeral port and need a unicast reply. */
        if (ntohs(from.sin_port) != MDNS_PORT) send_response(&from, get_u16be(packet));
    }
    return NULL;
}

static void *announce_thread(void *arg) {
    (void)arg;
    for (int i = 0;; i++) {
        announce();
        sleep(i < 3 ? 1 : 60);
    }
    return NULL;
}

int mdns_start(void) {
    char compact[13] = {0};
    int k = 0;
    for (const char *c = g_config.device_id; *c && k < 12; c++) {
        if (*c != ':') compact[k++] = (char)tolower((unsigned char)*c);
    }
    snprintf(host_label, sizeof(host_label), "vitaplay-%s", compact + (k > 8 ? k - 8 : 0));
    snprintf(instance_lower, sizeof(instance_lower), "%s.%s", g_config.name, SERVICE_TYPE);
    for (char *c = instance_lower; *c; c++) *c = (char)tolower((unsigned char)*c);
    snprintf(host_lower, sizeof(host_lower), "%s.local", host_label);

    sock = udp_bind(MDNS_PORT);
    if (sock < 0) return -1;
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MDNS_GROUP);
    mreq.imr_interface.s_addr = inet_addr(g_config.ip);
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
        vp_log("mDNS: joining multicast group failed");
    unsigned char ttl = 255;
    setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    struct in_addr iface;
    iface.s_addr = inet_addr(g_config.ip);
    setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &iface, sizeof(iface));

    spawn_thread(mdns_thread, NULL);
    spawn_thread(announce_thread, NULL);
    vp_log("mDNS advertising \"%s\" as %s.local", g_config.name, host_label);
    return 0;
}
