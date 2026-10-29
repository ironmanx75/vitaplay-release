#include "ntp.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define PT_REQUEST 210
#define PT_RESPONSE 211
#define PACKET_BYTES 32
#define ORIGINATE_OFFSET 8
#define RECEIVE_OFFSET 16
#define TRANSMIT_OFFSET 24
#define NTP_EPOCH_OFFSET 2208988800ULL

struct ntp_clock {
    int fd;
    struct sockaddr_in peer;
    bool has_peer;
    volatile bool stopping;
    int refs; /* receiver + sender threads */
};

static void ntp_release(ntp_clock *c) {
    if (__atomic_sub_fetch(&c->refs, 1, __ATOMIC_ACQ_REL) == 0) free(c);
}

static void ntp_now(uint8_t out[8]) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t seconds = (uint32_t)(tv.tv_sec + NTP_EPOCH_OFFSET);
    uint32_t fraction = (uint32_t)(((uint64_t)tv.tv_usec << 32) / 1000000);
    put_u32be(out, seconds);
    put_u32be(out + 4, fraction);
}

static void *ntp_receiver(void *arg) {
    ntp_clock *c = arg;
    uint8_t packet[256];
    while (!c->stopping) {
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int n = recvfrom(c->fd, packet, sizeof(packet), 0, (struct sockaddr *)&from, &from_len);
        if (n < 0) break;
        if (n < PACKET_BYTES || packet[1] != PT_REQUEST) continue;
        uint8_t response[PACKET_BYTES] = {0x80, PT_RESPONSE, 0, 7};
        memcpy(response + ORIGINATE_OFFSET, packet + TRANSMIT_OFFSET, 8);
        ntp_now(response + RECEIVE_OFFSET);
        ntp_now(response + TRANSMIT_OFFSET);
        sendto(c->fd, response, sizeof(response), 0, (struct sockaddr *)&from, from_len);
    }
    ntp_release(c);
    return NULL;
}

static void *ntp_sender(void *arg) {
    ntp_clock *c = arg;
    while (!c->stopping) {
        uint8_t request[PACKET_BYTES] = {0x80, PT_REQUEST, 0, 7};
        ntp_now(request + TRANSMIT_OFFSET);
        sendto(c->fd, request, sizeof(request), 0, (struct sockaddr *)&c->peer, sizeof(c->peer));
        for (int i = 0; i < 10 && !c->stopping; i++) usleep(100 * 1000);
    }
    ntp_release(c);
    return NULL;
}

ntp_clock *ntp_start(uint32_t peer_ip, int peer_port) {
    ntp_clock *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->fd = udp_bind(TIMING_PORT);
    if (c->fd < 0) {
        free(c);
        return NULL;
    }
    c->refs = 1;
    if (peer_port > 0) {
        c->peer.sin_family = AF_INET;
        c->peer.sin_port = htons(peer_port);
        c->peer.sin_addr.s_addr = peer_ip;
        c->has_peer = true;
        c->refs = 2;
        spawn_thread(ntp_sender, c);
    }
    spawn_thread(ntp_receiver, c);
    return c;
}

void ntp_stop(ntp_clock *clock) {
    if (!clock) return;
    /* Read the fd first: once stopping is set the threads may free the clock. */
    int fd = clock->fd;
    clock->stopping = true;
    shutdown(fd, SHUT_RDWR);
    close(fd);
}
