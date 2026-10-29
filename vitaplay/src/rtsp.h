/* RTSP/HTTP-style framing for the CarPlay control and event channels (port of RtspMessage.kt). */
#pragma once

#include "common.h"

#define RTSP_MAX_HEADERS 32

typedef struct {
    char method[32];   /* or "RTSP/1.0" for a response */
    char path[256];
    char protocol[16];
    int header_count;
    char header_name[RTSP_MAX_HEADERS][48]; /* lowercase */
    char header_value[RTSP_MAX_HEADERS][256];
    uint8_t *body;
    size_t body_len;
} rtsp_msg;

/* Parses one message from the front of buf. Returns bytes consumed, 0 if incomplete, -1 if bad. */
int rtsp_parse(const uint8_t *buf, size_t len, rtsp_msg *out);
void rtsp_free(rtsp_msg *msg);
const char *rtsp_header(const rtsp_msg *msg, const char *lowercase_name);

/* Appends a response that echoes the request's protocol and CSeq. */
void rtsp_response(buf_t *out, const rtsp_msg *request, int status, const char *content_type,
                   const uint8_t *body, size_t body_len);
