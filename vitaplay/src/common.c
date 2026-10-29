#include "common.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/rng.h>

vp_config g_config;

void buf_reserve(buf_t *b, size_t extra) {
    if (b->len + extra <= b->cap) return;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < b->len + extra) cap *= 2;
    uint8_t *data = realloc(b->data, cap);
    if (!data) abort();
    b->data = data;
    b->cap = cap;
}

void buf_append(buf_t *b, const void *data, size_t len) {
    if (!len) return;
    buf_reserve(b, len);
    memcpy(b->data + b->len, data, len);
    b->len += len;
}

void buf_append_str(buf_t *b, const char *s) { buf_append(b, s, strlen(s)); }

void buf_consume(buf_t *b, size_t n) {
    if (n >= b->len) {
        b->len = 0;
        return;
    }
    memmove(b->data, b->data + n, b->len - n);
    b->len -= n;
}

void buf_clear(buf_t *b) { b->len = 0; }

void buf_free(buf_t *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

#define LOG_LINES 64
static char log_ring[LOG_LINES][96];
static int log_next;
static int log_total;
static FILE *log_file;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

void log_init(void) {
    log_file = fopen(APP_DIR "/log.txt", "w");
}

void vp_log(const char *fmt, ...) {
    char line[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);

    pthread_mutex_lock(&log_lock);
    snprintf(log_ring[log_next], sizeof(log_ring[0]), "%s", line);
    log_next = (log_next + 1) % LOG_LINES;
    log_total++;
    if (log_file) {
        fprintf(log_file, "[%10llu] %s\n", (unsigned long long)(now_us() / 1000), line);
        fflush(log_file);
    }
    pthread_mutex_unlock(&log_lock);
}

int log_snapshot(char lines[][96], int max) {
    pthread_mutex_lock(&log_lock);
    int count = log_total < LOG_LINES ? log_total : LOG_LINES;
    if (count > max) count = max;
    for (int i = 0; i < count; i++) {
        int index = (log_next - count + i + LOG_LINES) % LOG_LINES;
        memcpy(lines[i], log_ring[index], sizeof(log_ring[0]));
    }
    pthread_mutex_unlock(&log_lock);
    return count;
}

uint64_t now_us(void) { return sceKernelGetProcessTimeWide(); }

void rand_bytes(void *out, size_t len) {
    uint8_t *p = out;
    while (len > 0) {
        size_t chunk = len > 64 ? 64 : len;
        sceKernelGetRandomNumber(p, chunk);
        p += chunk;
        len -= chunk;
    }
}

void hex_encode(char *out, const uint8_t *in, size_t len) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 0xf];
    }
    out[len * 2] = 0;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_decode(uint8_t *out, size_t max, const char *in) {
    size_t n = strlen(in);
    if (n % 2 || n / 2 > max) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hex_value(in[i * 2]), lo = hex_value(in[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return (int)(n / 2);
}

int tcp_listen(int port) {
    /* A reconnecting phone can race the previous session's cleanup, so retry for a second. */
    for (int attempt = 0; attempt < 10; attempt++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 && listen(fd, 4) == 0) return fd;
        close(fd);
        usleep(100 * 1000);
    }
    vp_log("tcp listen %d failed", port);
    return -1;
}

int udp_bind(int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        vp_log("udp bind %d failed", port);
        close(fd);
        return -1;
    }
    return fd;
}

int send_all(int fd, const void *data, size_t len) {
    const uint8_t *p = data;
    while (len > 0) {
        int sent = send(fd, p, len, 0);
        if (sent <= 0) return -1;
        p += sent;
        len -= sent;
    }
    return 0;
}

int recv_full(int fd, void *data, size_t len) {
    uint8_t *p = data;
    while (len > 0) {
        int got = recv(fd, p, len, 0);
        if (got == 0) return 0;
        if (got < 0) return -1;
        p += got;
        len -= got;
    }
    return 1;
}

int spawn_thread(void *(*fn)(void *), void *arg) {
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 512 * 1024);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int result = pthread_create(&thread, &attr, fn, arg);
    pthread_attr_destroy(&attr);
    return result;
}
