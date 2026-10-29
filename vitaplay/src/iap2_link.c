#include "iap2_link.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HEADER_BYTES 9
#define CHECKSUM_BYTES 1
#define SESSION_DESCRIPTOR_BYTES 3
#define SYNC_FIXED_BYTES 10
#define SYNC_VERSION 1
#define START_HIGH 0xff
#define START_LOW 0x5a
#define CONTROL_SYNCHRONIZE 0x80
#define CONTROL_ACKNOWLEDGEMENT 0x40
#define CONTROL_EXTENDED_ACKNOWLEDGEMENT 0x20
#define CONTROL_RESET 0x10
#define INITIAL_SEQUENCE 99
#define MARKER_RESEND_MS 1000
#define SYNC_RESEND_MS 500
#define DEFAULT_RETRANSMISSION_TIMEOUT_MS 4000
#define DEFAULT_MAX_RETRANSMISSIONS 4
#define DEFAULT_MAX_ACKNOWLEDGEMENTS 3
#define ACK_SLACK 10
#define EA_SESSION 11
#define FILE_TRANSFER_SESSION 12

static const uint8_t MARKER[6] = {0xff, 0x55, 0x02, 0x00, 0xee, 0x10};

typedef struct {
    int sequence;
    uint8_t session;
    uint8_t *payload;
    size_t len;
    int retransmissions;
    int64_t deadline_ms;
} packet;

typedef struct {
    packet *items;
    int count;
} packet_list;

typedef struct {
    iap2_link_event_type type;
    uint8_t *data;
    size_t len;
    bool writable;
    const char *reason;
} queued_event;

typedef struct {
    int length, control, sequence, acknowledgement, session;
} header;

struct iap2_link {
    iap2_link_config config;
    iap2_link_state state;
    iap2_link_sync peer;
    bool peer_received;
    int sent_sequence;
    int last_sent_acknowledged;   /* -1: none */
    int last_received_in_order;
    int last_acknowledged_received; /* -1: none */
    int accumulated_acknowledgements;
    bool writable;

    packet_list unacknowledged, queued, out_of_order;

    queued_event *events;
    int event_count;
    uint8_t *last_polled; /* payload of the event most recently returned by poll */
    char reason[96];

    uint8_t *output;
    size_t output_len, output_cap;

    uint8_t receive[IAP2_LINK_MAX_FRAME];
    size_t receive_head, receive_tail;
    bool awaiting_payload;
    header pending;

    int64_t marker_deadline, sync_deadline, send_ack_deadline, receive_ack_deadline; /* -1: none */
};

void iap2_link_config_wireless(iap2_link_config *c) {
    c->max_outgoing = 4;
    c->max_outgoing_delta = 0;
    c->acknowledgement_timeout_ms = 500;
    c->zero_acknowledgements = false;
    c->control_session_version = 2;
    c->max_queued_packets = 64;
    c->max_out_of_order_packets = 64;
    c->max_pending_output = 1048576;
    c->max_pending_events = 256;
}

void iap2_link_config_wired(iap2_link_config *c) {
    iap2_link_config_wireless(c);
    c->zero_acknowledgements = true;
}

/* ---- small helpers ---- */

static int dist(int sequence, int previous) { return previous < 0 ? 0 : (sequence - previous) & 0xff; }
static int next_seq(int sequence) { return (sequence + 1) & 0xff; }
static uint8_t checksum(const uint8_t *bytes, size_t count) {
    unsigned sum = 0;
    for (size_t i = 0; i < count; i++) sum += bytes[i];
    return (uint8_t)(-sum);
}
static bool checksum_valid(const uint8_t *bytes, size_t count) {
    unsigned sum = 0;
    for (size_t i = 0; i < count; i++) sum += bytes[i];
    return (sum & 0xff) == 0;
}
static int read_u16(const uint8_t *p) { return (p[0] << 8) | p[1]; }

static iap2_link_sync local_sync(const iap2_link *l) {
    iap2_link_sync s;
    s.max_outgoing = l->config.max_outgoing;
    s.max_length = IAP2_LINK_MAX_FRAME;
    s.retransmission_timeout_ms = l->config.zero_acknowledgements ? 0 : DEFAULT_RETRANSMISSION_TIMEOUT_MS;
    s.acknowledgement_timeout_ms = l->config.zero_acknowledgements ? 0 : l->config.acknowledgement_timeout_ms;
    s.max_retransmissions = l->config.zero_acknowledgements ? 0 : DEFAULT_MAX_RETRANSMISSIONS;
    s.max_acknowledgements = l->config.zero_acknowledgements ? 0 : DEFAULT_MAX_ACKNOWLEDGEMENTS;
    return s;
}

/* ---- packet lists ---- */

static bool list_push(packet_list *list, packet p, int limit) {
    if (list->count >= limit) return false;
    if (!list->items) list->items = calloc((size_t)limit, sizeof(packet));
    if (!list->items) return false;
    list->items[list->count++] = p;
    return true;
}

static packet list_remove(packet_list *list, int index) {
    packet p = list->items[index];
    memmove(&list->items[index], &list->items[index + 1], (size_t)(list->count - index - 1) * sizeof(packet));
    list->count--;
    return p;
}

static void list_clear(packet_list *list) {
    for (int i = 0; i < list->count; i++) free(list->items[i].payload);
    list->count = 0;
}

/* ---- output, events, death ---- */

static void clear_events(iap2_link *l) {
    for (int i = 0; i < l->event_count; i++) free(l->events[i].data);
    l->event_count = 0;
}

static void die(iap2_link *l, const char *reason) {
    if (l->state == IAP2_LINK_DEAD) return;
    l->marker_deadline = l->sync_deadline = l->send_ack_deadline = l->receive_ack_deadline = -1;
    l->state = IAP2_LINK_DEAD;
    l->writable = false;
    l->output_len = 0;
    clear_events(l);
    if (reason && reason != l->reason) snprintf(l->reason, sizeof(l->reason), "%s", reason);
    queued_event *e = &l->events[l->event_count++]; /* capacity is at least 1 */
    memset(e, 0, sizeof(*e));
    e->type = IAP2_LINK_EVENT_DEAD;
    e->reason = reason ? l->reason : NULL;
}

static bool append_output(iap2_link *l, const uint8_t *bytes, size_t len) {
    if (l->state == IAP2_LINK_DEAD) return false;
    if (len > l->config.max_pending_output - l->output_len) {
        die(l, "iAP2 pending output limit exceeded");
        return false;
    }
    if (l->output_len + len > l->output_cap) {
        size_t cap = l->output_cap ? l->output_cap : 1024;
        while (cap < l->output_len + len) cap *= 2;
        uint8_t *grown = realloc(l->output, cap);
        if (!grown) {
            die(l, "iAP2 output allocation failed");
            return false;
        }
        l->output = grown;
        l->output_cap = cap;
    }
    memcpy(l->output + l->output_len, bytes, len);
    l->output_len += len;
    return true;
}

/* Takes ownership of data. */
static void enqueue_event(iap2_link *l, iap2_link_event_type type, uint8_t *data, size_t len, bool writable) {
    if (l->state == IAP2_LINK_DEAD) {
        free(data);
        return;
    }
    if (l->event_count >= l->config.max_pending_events) {
        free(data);
        die(l, "iAP2 pending event limit exceeded");
        return;
    }
    queued_event *e = &l->events[l->event_count++];
    e->type = type;
    e->data = data;
    e->len = len;
    e->writable = writable;
    e->reason = NULL;
}

static void set_writable(iap2_link *l, bool value) {
    if (l->writable == value) return;
    l->writable = value;
    enqueue_event(l, IAP2_LINK_EVENT_WRITABLE, NULL, 0, value);
}

/* ---- framing ---- */

static void write_packet(iap2_link *l, const uint8_t *payload, size_t len, int sequence, int control, int session) {
    if (l->state == IAP2_LINK_DEAD) return;
    l->accumulated_acknowledgements = 0;
    size_t length = payload ? len + HEADER_BYTES + CHECKSUM_BYTES : HEADER_BYTES;
    uint8_t h[HEADER_BYTES];
    h[0] = START_HIGH;
    h[1] = START_LOW;
    h[2] = (uint8_t)(length >> 8);
    h[3] = (uint8_t)length;
    h[4] = (uint8_t)control;
    h[5] = (uint8_t)sequence;
    h[6] = (uint8_t)l->last_received_in_order;
    h[7] = (uint8_t)session;
    h[8] = checksum(h, HEADER_BYTES - CHECKSUM_BYTES);
    if (!append_output(l, h, HEADER_BYTES) || !payload) return;
    uint8_t sum = checksum(payload, len);
    if (append_output(l, payload, len)) append_output(l, &sum, 1);
}

static void send_synchronization(iap2_link *l) {
    iap2_link_sync s = local_sync(l);
    uint8_t p[SYNC_FIXED_BYTES + 3 * SESSION_DESCRIPTOR_BYTES] = {
        SYNC_VERSION, s.max_outgoing,
        (uint8_t)(s.max_length >> 8), (uint8_t)s.max_length,
        (uint8_t)(s.retransmission_timeout_ms >> 8), (uint8_t)s.retransmission_timeout_ms,
        (uint8_t)(s.acknowledgement_timeout_ms >> 8), (uint8_t)s.acknowledgement_timeout_ms,
        s.max_retransmissions, s.max_acknowledgements,
        IAP2_LINK_CONTROL_SESSION, 0, l->config.control_session_version,
        EA_SESSION, 2, 1,
        FILE_TRANSFER_SESSION, 1, 2,
    };
    write_packet(l, p, sizeof(p), l->sent_sequence, CONTROL_SYNCHRONIZE, 0);
}

static void send_acknowledgement(iap2_link *l) {
    write_packet(l, NULL, 0, l->sent_sequence, CONTROL_ACKNOWLEDGEMENT, 0);
}

static void send_extended_acknowledgement(iap2_link *l, const uint8_t *missing, size_t count) {
    write_packet(l, missing, count, l->sent_sequence, CONTROL_EXTENDED_ACKNOWLEDGEMENT, 0);
}

static void send_data(iap2_link *l, const packet *p) {
    write_packet(l, p->payload, p->len, p->sequence, CONTROL_ACKNOWLEDGEMENT, p->session);
}

static bool peer_limits_usable(const iap2_link *l) { return l->peer.max_length > HEADER_BYTES + CHECKSUM_BYTES; }

static bool peer_payload_acceptable(const iap2_link *l, size_t len) {
    return peer_limits_usable(l) && len <= (size_t)(l->peer.max_length - HEADER_BYTES - CHECKSUM_BYTES);
}

/* ---- sending ---- */

/* Takes ownership of p.payload. */
static void send_packet(iap2_link *l, packet p, int64_t now) {
    if (l->state != IAP2_LINK_NORMAL || dist(l->sent_sequence, l->last_sent_acknowledged) > l->peer.max_outgoing) {
        if (!list_push(&l->queued, p, l->config.max_queued_packets)) {
            free(p.payload);
            die(l, "iAP2 outbound queue limit exceeded");
        } else {
            set_writable(l, false);
        }
        return;
    }
    l->sent_sequence = next_seq(l->sent_sequence);
    p.sequence = l->sent_sequence;
    p.retransmissions = 0;
    p.deadline_ms = now + l->peer.retransmission_timeout_ms;
    l->send_ack_deadline = -1;
    send_data(l, &p);
    l->last_acknowledged_received = l->last_received_in_order;
    if (l->peer.max_retransmissions > 0) {
        if (!list_push(&l->unacknowledged, p, 256)) {
            free(p.payload);
            die(l, "iAP2 unacknowledged packet limit exceeded");
            return;
        }
        l->receive_ack_deadline = p.deadline_ms;
    } else {
        l->last_sent_acknowledged = l->sent_sequence;
        free(p.payload);
    }
}

static void retransmit_due_packet(iap2_link *l, int64_t now) {
    if (l->state != IAP2_LINK_NORMAL || l->unacknowledged.count == 0) return;
    int next = 0;
    for (int i = 1; i < l->unacknowledged.count; i++)
        if (l->unacknowledged.items[i].deadline_ms < l->unacknowledged.items[next].deadline_ms) next = i;
    int64_t second = -1;
    for (int i = 0; i < l->unacknowledged.count; i++) {
        if (i == next) continue;
        int64_t d = l->unacknowledged.items[i].deadline_ms;
        if (second < 0 || d < second) second = d;
    }
    packet *p = &l->unacknowledged.items[next];
    p->deadline_ms = now + l->peer.retransmission_timeout_ms;
    p->retransmissions++;
    if (p->retransmissions == l->peer.max_retransmissions) {
        snprintf(l->reason, sizeof(l->reason), "iAP2 packet %d was not acknowledged", p->sequence);
        die(l, l->reason);
        return;
    }
    send_data(l, p);
    l->receive_ack_deadline = second >= 0 ? second : p->deadline_ms;
}

/* ---- receiving ---- */

static void enter_negotiating(iap2_link *l, int64_t now) {
    l->state = IAP2_LINK_NEGOTIATING;
    l->marker_deadline = -1;
    send_synchronization(l);
    if (l->state != IAP2_LINK_DEAD) l->sync_deadline = now + SYNC_RESEND_MS;
}

static void handle_synchronization(iap2_link *l, const uint8_t *p, size_t len, int sequence) {
    if (l->state != IAP2_LINK_NEGOTIATING) return;
    if (len < SYNC_FIXED_BYTES || p[0] != SYNC_VERSION) return;
    l->peer.max_outgoing = p[1];
    l->peer.max_length = (uint16_t)read_u16(p + 2);
    l->peer.retransmission_timeout_ms = (uint16_t)read_u16(p + 4);
    l->peer.acknowledgement_timeout_ms = (uint16_t)read_u16(p + 6);
    l->peer.max_retransmissions = p[8];
    l->peer.max_acknowledgements = p[9];
    l->peer_received = true;
    l->last_received_in_order = sequence;
    l->last_acknowledged_received = sequence;
    send_acknowledgement(l);
}

static void handle_acknowledgement(iap2_link *l, int acknowledgement, int64_t now) {
    if (l->state == IAP2_LINK_NEGOTIATING) {
        bool queued_ok = true;
        for (int i = 0; i < l->queued.count; i++)
            if (!peer_payload_acceptable(l, l->queued.items[i].len)) queued_ok = false;
        if (!l->peer_received || !peer_limits_usable(l) || !queued_ok) {
            die(l, "peer iAP2 maxLength cannot carry pending control packets");
            return;
        }
        l->state = IAP2_LINK_NORMAL;
        l->sync_deadline = -1;
        set_writable(l, true);
    }
    l->last_sent_acknowledged = acknowledgement;

    bool rearmed = false;
    while (l->unacknowledged.count > 0) {
        packet *first = &l->unacknowledged.items[0];
        int d = dist(first->sequence, l->last_sent_acknowledged);
        if (d > 0 && d <= l->peer.max_acknowledgements + ACK_SLACK) {
            l->receive_ack_deadline = first->deadline_ms;
            rearmed = true;
            break;
        }
        free(list_remove(&l->unacknowledged, 0).payload);
    }
    if (!rearmed) l->receive_ack_deadline = -1;

    while (dist(l->sent_sequence, l->last_sent_acknowledged) < l->peer.max_outgoing && l->queued.count > 0) {
        send_packet(l, list_remove(&l->queued, 0), now);
        set_writable(l, true);
    }
}

static void handle_extended_acknowledgement(iap2_link *l, const uint8_t *missing, size_t count) {
    if (l->state != IAP2_LINK_NORMAL) return;
    for (int i = 0; i < l->unacknowledged.count; i++) {
        packet *p = &l->unacknowledged.items[i];
        bool listed = false;
        for (size_t m = 0; m < count; m++)
            if (missing[m] == p->sequence) listed = true;
        if (!listed) continue;
        p->retransmissions++;
        if (p->retransmissions == l->peer.max_retransmissions) {
            snprintf(l->reason, sizeof(l->reason), "iAP2 packet %d was not acknowledged", p->sequence);
            die(l, l->reason);
            return;
        }
        send_data(l, p);
        l->send_ack_deadline = -1;
        l->receive_ack_deadline = p->deadline_ms;
    }
}

/* Takes ownership of p.payload. */
static void handle_data(iap2_link *l, packet p, int64_t now) {
    int d = dist(p.sequence, l->last_received_in_order);
    if (d == 0 || d > l->peer.max_outgoing + ACK_SLACK) {
        free(p.payload);
        send_acknowledgement(l);
        return;
    }
    for (int i = 0; i < l->out_of_order.count; i++) {
        if (l->out_of_order.items[i].sequence == p.sequence) {
            free(p.payload);
            return;
        }
    }
    if (!list_push(&l->out_of_order, p, l->config.max_out_of_order_packets)) {
        free(p.payload);
        die(l, "iAP2 out-of-order packet limit exceeded");
        return;
    }
    if (d > 1) {
        if (d >= l->peer.max_outgoing) {
            uint8_t missing[256];
            size_t count = 0;
            int sequence = l->last_received_in_order;
            while (dist(p.sequence, sequence) > 1 && count < sizeof(missing)) {
                sequence = next_seq(sequence);
                missing[count++] = (uint8_t)sequence;
            }
            l->send_ack_deadline = -1;
            send_extended_acknowledgement(l, missing, count);
        }
        return;
    }

    /* Sort by distance from the last in-order packet (insertion sort; the list is small). */
    packet_list *o = &l->out_of_order;
    for (int i = 1; i < o->count; i++) {
        packet key = o->items[i];
        int kd = dist(key.sequence, l->last_received_in_order);
        int j = i - 1;
        while (j >= 0 && dist(o->items[j].sequence, l->last_received_in_order) > kd) {
            o->items[j + 1] = o->items[j];
            j--;
        }
        o->items[j + 1] = key;
    }
    while (o->count > 0 && dist(o->items[0].sequence, l->last_received_in_order) == 1) {
        packet in_order = list_remove(o, 0);
        l->last_received_in_order = in_order.sequence;
        if (in_order.session == IAP2_LINK_CONTROL_SESSION)
            enqueue_event(l, IAP2_LINK_EVENT_CONTROL, in_order.payload, in_order.len, false);
        else
            free(in_order.payload);
    }

    if (l->peer.max_acknowledgements == 0) return;
    int window = l->peer.max_outgoing - l->config.max_outgoing_delta;
    if (window < 1) window = 1;
    if (dist(l->last_received_in_order, l->last_acknowledged_received) >= window) {
        l->send_ack_deadline = -1;
        l->last_acknowledged_received = l->last_received_in_order;
        send_acknowledgement(l);
    } else {
        l->send_ack_deadline = now + l->peer.acknowledgement_timeout_ms;
    }
}

/* payload/len: the frame's payload without its checksum, or NULL for a header-only frame. */
static void process_frame(iap2_link *l, const header *h, const uint8_t *payload, size_t len, int64_t now) {
    if (h->control & CONTROL_RESET) {
        die(l, "peer sent iAP2 reset");
        return;
    }
    if (h->control & CONTROL_SYNCHRONIZE) handle_synchronization(l, payload ? payload : (const uint8_t *)"", payload ? len : 0, h->sequence);
    if (h->control & CONTROL_ACKNOWLEDGEMENT) {
        l->accumulated_acknowledgements++;
        handle_acknowledgement(l, h->acknowledgement, now);
    }
    if ((h->control & CONTROL_EXTENDED_ACKNOWLEDGEMENT) && payload) handle_extended_acknowledgement(l, payload, len);
    if ((h->control & ~CONTROL_ACKNOWLEDGEMENT) == 0 && payload) {
        packet p = {h->sequence, (uint8_t)h->session, malloc(len ? len : 1), len, 0, 0};
        if (!p.payload) {
            die(l, "iAP2 receive allocation failed");
            return;
        }
        memcpy(p.payload, payload, len);
        handle_data(l, p, now);
    }
    if (l->peer.max_acknowledgements > 0 && l->accumulated_acknowledgements >= l->peer.max_acknowledgements) {
        l->accumulated_acknowledgements = 0;
        l->last_acknowledged_received = l->last_received_in_order;
        send_acknowledgement(l);
    }
}

static size_t rx_size(const iap2_link *l) { return l->receive_tail - l->receive_head; }

static void rx_discard(iap2_link *l, size_t count) {
    l->receive_head += count;
    if (l->receive_head == l->receive_tail) l->receive_head = l->receive_tail = 0;
}

static size_t rx_room(iap2_link *l) {
    if (l->receive_head) {
        memmove(l->receive, l->receive + l->receive_head, rx_size(l));
        l->receive_tail -= l->receive_head;
        l->receive_head = 0;
    }
    return sizeof(l->receive) - l->receive_tail;
}

/* Parses one item from the receive buffer; returns false when nothing more can be parsed yet. */
static bool parse_available(iap2_link *l, int64_t now) {
    if (l->state == IAP2_LINK_DEAD) return false;
    const uint8_t *rx = l->receive + l->receive_head;
    if (l->state == IAP2_LINK_DETECTING) {
        if (rx_size(l) < sizeof(MARKER)) return false;
        if (memcmp(rx, MARKER, sizeof(MARKER)) != 0) {
            die(l, "iAP2 marker was not received");
            return false;
        }
        rx_discard(l, sizeof(MARKER));
        enter_negotiating(l, now);
        return true;
    }

    if (l->awaiting_payload) {
        size_t need = (size_t)l->pending.length - HEADER_BYTES;
        if (rx_size(l) < need) return false;
        header h = l->pending;
        l->awaiting_payload = false;
        /* Copy out before processing: processing may write output but never touches receive. */
        uint8_t *payload = malloc(need);
        if (!payload) {
            die(l, "iAP2 receive allocation failed");
            return false;
        }
        memcpy(payload, rx, need);
        rx_discard(l, need);
        if (checksum_valid(payload, need)) process_frame(l, &h, payload, need - CHECKSUM_BYTES, now);
        free(payload);
        return true;
    }

    bool discarded = false;
    while (rx_size(l) >= 2 && (l->receive[l->receive_head] != START_HIGH || l->receive[l->receive_head + 1] != START_LOW)) {
        rx_discard(l, 1);
        discarded = true;
    }
    if (rx_size(l) < HEADER_BYTES) return discarded;
    uint8_t raw[HEADER_BYTES];
    memcpy(raw, l->receive + l->receive_head, HEADER_BYTES);
    rx_discard(l, HEADER_BYTES);
    if (!checksum_valid(raw, HEADER_BYTES)) return true;
    header h = {read_u16(raw + 2), raw[4], raw[5], raw[6], raw[7]};
    if (h.length < HEADER_BYTES) return true;
    if (h.length == HEADER_BYTES) {
        process_frame(l, &h, NULL, 0, now);
    } else {
        l->pending = h;
        l->awaiting_payload = true;
    }
    return true;
}

/* ---- public API ---- */

iap2_link *iap2_link_new(const iap2_link_config *config) {
    iap2_link *l = calloc(1, sizeof(*l));
    if (!l) return NULL;
    l->config = *config;
    if (l->config.max_pending_events < 1) l->config.max_pending_events = 1;
    l->events = calloc((size_t)l->config.max_pending_events + 1, sizeof(queued_event));
    if (!l->events) {
        free(l);
        return NULL;
    }
    l->state = IAP2_LINK_IDLE;
    l->peer = local_sync(l);
    l->sent_sequence = INITIAL_SEQUENCE;
    l->last_sent_acknowledged = -1;
    l->last_acknowledged_received = -1;
    l->marker_deadline = l->sync_deadline = l->send_ack_deadline = l->receive_ack_deadline = -1;
    return l;
}

void iap2_link_free(iap2_link *l) {
    if (!l) return;
    list_clear(&l->unacknowledged);
    list_clear(&l->queued);
    list_clear(&l->out_of_order);
    free(l->unacknowledged.items);
    free(l->queued.items);
    free(l->out_of_order.items);
    clear_events(l);
    free(l->events);
    free(l->last_polled);
    free(l->output);
    free(l);
}

void iap2_link_start(iap2_link *l, bool initiator, int64_t now) {
    if (l->state != IAP2_LINK_IDLE) return;
    l->state = IAP2_LINK_DETECTING;
    if (!append_output(l, MARKER, sizeof(MARKER))) return;
    l->marker_deadline = now + MARKER_RESEND_MS;
    if (initiator && l->state != IAP2_LINK_DEAD) enter_negotiating(l, now);
}

void iap2_link_feed(iap2_link *l, const uint8_t *data, size_t len, int64_t now) {
    size_t offset = 0;
    while (offset < len && l->state != IAP2_LINK_DEAD) {
        size_t room = rx_room(l);
        if (room == 0) {
            if (!parse_available(l, now)) {
                die(l, "iAP2 inbound frame exceeds 65535 bytes");
                return;
            }
            continue;
        }
        size_t count = len - offset < room ? len - offset : room;
        memcpy(l->receive + l->receive_tail, data + offset, count);
        l->receive_tail += count;
        offset += count;
        while (parse_available(l, now) && l->state != IAP2_LINK_DEAD) {
        }
    }
}

void iap2_link_feed_eof(iap2_link *l) { die(l, NULL); }

int64_t iap2_link_next_deadline(const iap2_link *l) {
    int64_t deadlines[4] = {l->marker_deadline, l->sync_deadline, l->send_ack_deadline, l->receive_ack_deadline};
    int64_t best = -1;
    for (int i = 0; i < 4; i++)
        if (deadlines[i] >= 0 && (best < 0 || deadlines[i] < best)) best = deadlines[i];
    return best;
}

void iap2_link_advance(iap2_link *l, int64_t now) {
    while (l->state != IAP2_LINK_DEAD) {
        int64_t deadline = iap2_link_next_deadline(l);
        if (deadline < 0 || deadline > now) return;
        if (l->marker_deadline >= 0 && l->marker_deadline <= now) {
            l->marker_deadline = -1;
            if (l->state == IAP2_LINK_DETECTING && append_output(l, MARKER, sizeof(MARKER)))
                l->marker_deadline = now + MARKER_RESEND_MS;
        } else if (l->sync_deadline >= 0 && l->sync_deadline <= now) {
            l->sync_deadline = -1;
            if (l->state == IAP2_LINK_NEGOTIATING) {
                send_synchronization(l);
                if (l->state != IAP2_LINK_DEAD) l->sync_deadline = now + SYNC_RESEND_MS;
            }
        } else if (l->send_ack_deadline >= 0 && l->send_ack_deadline <= now) {
            l->send_ack_deadline = -1;
            if (l->state == IAP2_LINK_NORMAL) {
                l->last_acknowledged_received = l->last_received_in_order;
                send_acknowledgement(l);
            }
        } else if (l->receive_ack_deadline >= 0 && l->receive_ack_deadline <= now) {
            l->receive_ack_deadline = -1;
            retransmit_due_packet(l, now);
        }
    }
}

int iap2_link_send_control(iap2_link *l, const uint8_t *data, size_t len, int64_t now) {
    if (len > IAP2_LINK_MAX_PAYLOAD) return -1;
    if ((l->peer_received || l->state == IAP2_LINK_NORMAL) && !peer_payload_acceptable(l, len)) return -1;
    packet p = {0, IAP2_LINK_CONTROL_SESSION, malloc(len ? len : 1), len, 0, 0};
    if (!p.payload) return -1;
    memcpy(p.payload, data, len);
    send_packet(l, p, now);
    return 0;
}

size_t iap2_link_output(iap2_link *l, uint8_t *buf, size_t max) {
    size_t n = l->output_len < max ? l->output_len : max;
    memcpy(buf, l->output, n);
    memmove(l->output, l->output + n, l->output_len - n);
    l->output_len -= n;
    return n;
}

size_t iap2_link_output_pending(const iap2_link *l) { return l->output_len; }

bool iap2_link_poll_event(iap2_link *l, iap2_link_event *event) {
    free(l->last_polled);
    l->last_polled = NULL;
    if (l->event_count == 0) {
        memset(event, 0, sizeof(*event));
        return false;
    }
    queued_event e = l->events[0];
    memmove(&l->events[0], &l->events[1], (size_t)(l->event_count - 1) * sizeof(queued_event));
    l->event_count--;
    l->last_polled = e.data;
    event->type = e.type;
    event->data = e.data;
    event->len = e.len;
    event->writable = e.writable;
    event->reason = e.reason;
    return true;
}

iap2_link_state iap2_link_get_state(const iap2_link *l) { return l->state; }
bool iap2_link_writable(const iap2_link *l) { return l->writable; }
iap2_link_sync iap2_link_peer_sync(const iap2_link *l) { return l->peer; }
