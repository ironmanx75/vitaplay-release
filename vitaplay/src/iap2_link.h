/*
 * iAP2 link layer (port of PlayPort's Iap2LinkEngine.kt): a pure state machine with no I/O,
 * threads or clock of its own.
 *
 * The caller passes a monotonic millisecond clock to every call, writes what iap2_link_output()
 * returns to its byte stream, feeds received fragments through iap2_link_feed(), and calls
 * iap2_link_advance() when iap2_link_next_deadline() is reached. Only control-session (session 10)
 * payloads are surfaced, as IAP2_LINK_EVENT_CONTROL events.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define IAP2_LINK_CONTROL_SESSION 10
#define IAP2_LINK_MAX_FRAME 0xffff
#define IAP2_LINK_MAX_PAYLOAD (IAP2_LINK_MAX_FRAME - 9 - 1) /* frame minus header and checksum */

typedef enum {
    IAP2_LINK_IDLE,
    IAP2_LINK_DETECTING,
    IAP2_LINK_NEGOTIATING,
    IAP2_LINK_NORMAL,
    IAP2_LINK_DEAD,
} iap2_link_state;

typedef struct {
    uint8_t max_outgoing;
    uint8_t max_outgoing_delta;
    uint16_t acknowledgement_timeout_ms;
    bool zero_acknowledgements;
    uint8_t control_session_version;
    int max_queued_packets;       /* 1..256 */
    int max_out_of_order_packets; /* 1..256 */
    size_t max_pending_output;
    int max_pending_events;
} iap2_link_config;

/* Bluetooth RFCOMM: acknowledgements on, the phone initiates synchronization. */
void iap2_link_config_wireless(iap2_link_config *config);
/* USB and the AirPlay type-130 tunnel: zero-acknowledgement mode, the accessory initiates. */
void iap2_link_config_wired(iap2_link_config *config);

typedef enum {
    IAP2_LINK_EVENT_NONE,
    IAP2_LINK_EVENT_CONTROL,  /* data/len: one control-session payload */
    IAP2_LINK_EVENT_WRITABLE, /* writable: whether sends go out now or are queued */
    IAP2_LINK_EVENT_DEAD,     /* reason: why the link ended, or NULL for end of stream */
} iap2_link_event_type;

typedef struct {
    iap2_link_event_type type;
    const uint8_t *data; /* valid until the next iap2_link_poll_event() or iap2_link_free() */
    size_t len;
    bool writable;
    const char *reason;
} iap2_link_event;

/* The synchronization parameters a peer advertised. */
typedef struct {
    uint8_t max_outgoing;
    uint16_t max_length;
    uint16_t retransmission_timeout_ms;
    uint16_t acknowledgement_timeout_ms;
    uint8_t max_retransmissions;
    uint8_t max_acknowledgements;
} iap2_link_sync;

typedef struct iap2_link iap2_link;

iap2_link *iap2_link_new(const iap2_link_config *config);
void iap2_link_free(iap2_link *link);

/* Starts a link attempt: sends the iAP2 marker; an initiator also starts synchronization. */
void iap2_link_start(iap2_link *link, bool initiator, int64_t now_ms);
/* Supplies received bytes (any fragmentation). */
void iap2_link_feed(iap2_link *link, const uint8_t *data, size_t len, int64_t now_ms);
/* The byte stream ended. */
void iap2_link_feed_eof(iap2_link *link);
/* Runs every timer due at now_ms. */
void iap2_link_advance(iap2_link *link, int64_t now_ms);
/* The next timer deadline, or -1 when none is armed. */
int64_t iap2_link_next_deadline(const iap2_link *link);

/* Queues one control-session payload. Returns 0, or -1 if it is too large for the peer. */
int iap2_link_send_control(iap2_link *link, const uint8_t *data, size_t len, int64_t now_ms);

/* Copies up to max pending output bytes into buf and removes them; returns the count. */
size_t iap2_link_output(iap2_link *link, uint8_t *buf, size_t max);
size_t iap2_link_output_pending(const iap2_link *link);

/* Returns false when no event is pending. */
bool iap2_link_poll_event(iap2_link *link, iap2_link_event *event);

iap2_link_state iap2_link_get_state(const iap2_link *link);
bool iap2_link_writable(const iap2_link *link);
iap2_link_sync iap2_link_peer_sync(const iap2_link *link);
