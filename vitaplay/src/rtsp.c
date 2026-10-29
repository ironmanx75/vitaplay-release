#include "rtsp.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t *find_header_end(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i + 4 <= len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return buf + i;
        }
    }
    return NULL;
}

static void copy_trimmed(char *out, size_t max, const char *start, const char *end) {
    while (start < end && isspace((unsigned char)*start)) start++;
    while (end > start && isspace((unsigned char)end[-1])) end--;
    size_t n = (size_t)(end - start);
    if (n >= max) n = max - 1;
    memcpy(out, start, n);
    out[n] = 0;
}

int rtsp_parse(const uint8_t *buf, size_t len, rtsp_msg *out) {
    memset(out, 0, sizeof(*out));
    const uint8_t *end = find_header_end(buf, len);
    if (!end) return len > 64 * 1024 ? -1 : 0;

    const char *text = (const char *)buf;
    const char *head_end = (const char *)end;
    const char *line_end = memchr(text, '\r', head_end - text + 1);
    if (!line_end) return -1;

    /* Request line: METHOD PATH PROTOCOL (or PROTOCOL STATUS TEXT for responses). */
    const char *p = text;
    const char *sp1 = memchr(p, ' ', line_end - p);
    if (!sp1) return -1;
    copy_trimmed(out->method, sizeof(out->method), p, sp1);
    const char *sp2 = memchr(sp1 + 1, ' ', line_end - sp1 - 1);
    copy_trimmed(out->path, sizeof(out->path), sp1 + 1, sp2 ? sp2 : line_end);
    if (sp2) copy_trimmed(out->protocol, sizeof(out->protocol), sp2 + 1, line_end);
    else strcpy(out->protocol, "RTSP/1.0");

    size_t content_length = 0;
    p = line_end + 2;
    while (p < head_end) {
        const char *next = memchr(p, '\r', head_end - p);
        if (!next) next = head_end;
        const char *colon = memchr(p, ':', next - p);
        if (colon && out->header_count < RTSP_MAX_HEADERS) {
            int h = out->header_count++;
            copy_trimmed(out->header_name[h], sizeof(out->header_name[h]), p, colon);
            for (char *c = out->header_name[h]; *c; c++) *c = (char)tolower((unsigned char)*c);
            copy_trimmed(out->header_value[h], sizeof(out->header_value[h]), colon + 1, next);
            if (strcmp(out->header_name[h], "content-length") == 0) {
                long value = strtol(out->header_value[h], NULL, 10);
                content_length = value > 0 ? (size_t)value : 0;
            }
        }
        p = next + 2;
    }

    size_t body_start = (size_t)((const uint8_t *)head_end - buf) + 4;
    if (content_length > 16 * 1024 * 1024) return -1;
    if (body_start + content_length > len) return 0;
    out->body_len = content_length;
    out->body = malloc(content_length ? content_length : 1);
    if (content_length) memcpy(out->body, buf + body_start, content_length);
    return (int)(body_start + content_length);
}

void rtsp_free(rtsp_msg *msg) {
    free(msg->body);
    msg->body = NULL;
}

const char *rtsp_header(const rtsp_msg *msg, const char *name) {
    for (int i = 0; i < msg->header_count; i++) {
        if (strcmp(msg->header_name[i], name) == 0) return msg->header_value[i];
    }
    return NULL;
}

static const char *status_text(int status) {
    switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 500: return "Internal Server Error";
    default: return "OK";
    }
}

void rtsp_response(buf_t *out, const rtsp_msg *request, int status, const char *content_type,
                   const uint8_t *body, size_t body_len) {
    char head[512];
    int n = snprintf(head, sizeof(head), "%s %d %s\r\n", request->protocol[0] ? request->protocol : "RTSP/1.0",
                     status, status_text(status));
    if (content_type) n += snprintf(head + n, sizeof(head) - n, "Content-Type: %s\r\n", content_type);
    const char *cseq = rtsp_header(request, "cseq");
    if (cseq) n += snprintf(head + n, sizeof(head) - n, "CSeq: %s\r\n", cseq);
    snprintf(head + n, sizeof(head) - n, "Content-Length: %u\r\n\r\n", (unsigned)body_len);
    buf_append_str(out, head);
    buf_append(out, body, body_len);
}
