/*
 * l2capprobe: the RX-interception spike for VitaPlay's on-device Bluetooth bootstrap.
 *
 * It answers one make-or-break question: can a kernel plugin SEE SceBt's incoming L2CAP signaling
 * PDUs by hooking the stack? If yes, the tier-3 plan (open our own L2CAP channel -> RFCOMM -> iAP2)
 * is viable, because channel setup is all L2CAP signaling (connection response, config, echo).
 *
 * Reverse-engineering (this Vita's SceBt, firmware 3.65, segment 0 loads at VA 0x02100000):
 *   - The BT RX event loop (sub_0211BA30) reassembles ACL/L2CAP and, for signaling, calls
 *     sub_02111418 -> sub_02106558(r0=connection, r1=signaling-PDU, r2=len).
 *   - sub_02106558 is therefore the incoming-L2CAP-signaling handler. Its segment-0 offset is
 *     0x02106558 - 0x02100000 = 0x6558 (ASLR moves the base, but the offset is fixed).
 * We hook it with taiHookFunctionOffsetForKernel and log each PDU. The hook runs in the BT RX
 * thread, so it only copies into a ring buffer; a worker thread writes the log file.
 *
 * An L2CAP signaling PDU is: [code][id][len_lo][len_hi][payload...]. Codes we care about:
 *   0x02 CONNECTION_REQ  0x03 CONNECTION_RSP  0x04 CONFIG_REQ  0x05 CONFIG_RSP
 *   0x06 DISCONNECT_REQ  0x07 DISCONNECT_RSP  0x08 ECHO_REQ    0x09 ECHO_RSP  0x0A INFO_REQ
 *
 * Observation only: it does NOT inject, connect, or modify anything. Load at runtime, never at boot.
 */
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysmem.h>   /* ksceKernelCopyFromUser / ksceKernelCopyToUser */
#include <psp2kern/io/fcntl.h>
#include <psp2kern/io/stat.h>
#include <psp2kern/bt.h>
#include <stdarg.h>
#include <taihen.h>

#define LOG_PATH "ux0:data/VitaPlay/l2capprobe.log"

/* sub_02106558 (incoming L2CAP signaling handler) within SceBt segment 0, firmware 3.65. */
#define SCEBT_L2CAP_SIG_SEGMENT 0
#define SCEBT_L2CAP_SIG_OFFSET 0x6558

static tai_hook_ref_t g_sig_ref;
static SceUID g_sig_hook = -1;
static SceUID g_thread = -1;
static SceUID g_bt_thread = -1;
static volatile int g_exiting;

/* ---- SceBt internals for the RFCOMM CONNECTION_REQUEST experiment (3.65) ----
 * Resolved at runtime from the module's segment bases (kernel ASLR moves them).
 * seg0 = text (functions), seg1 = data (state block at seg1+0x10).
 *   sub_0211B6B4 (seg0+0x1b6b4)  BT state lock, returns 0 on success     -> bt_lock
 *   sub_0211B7A0 (seg0+0x1b7a0)  BT state unlock                         -> bt_unlock
 *   sub_02111420 (seg0+0x11420)  get connection obj: (state,type=1,mac0,mac1) -> conn_get
 *   sub_02106422 (seg0+0x6422)   send L2CAP CONNECTION_REQUEST: (conn, chan, _, flags)
 *                                 chan[0x34]=PSM, chan[0x36]=source CID  -> conn_req
 * This mirrors how ksceBtSendL2capEchoRequestForTest works (lock -> conn_get -> send -> unlock),
 * only sending a real CONNECTION_REQUEST instead of an echo. */
typedef int   (*bt_lock_fn)(void);
typedef void  (*bt_unlock_fn)(void);
typedef void *(*conn_get_fn)(void *state, int type, unsigned int mac0, unsigned int mac1);
typedef int   (*conn_req_fn)(void *conn, void *chan, int unused, int flags);
/* sub_02106384 (seg0+0x6384): send L2CAP CONFIG_REQUEST. chan[0x38]=remote dcid, chan[8]=0 -> no
 * options (accept defaults). */
typedef int   (*config_req_fn)(void *conn, void *chan);
/* sub_02111544 (seg0+0x11544): find/create an L2CAP/RFCOMM channel object on a connection.
 * (conn, type, key) -> channel ptr. type 4=inbound, 5=outbound, 7=RFCOMM; +0x10 = create.
 * Creating a type-5 (0x15) channel for our scid makes SceBt's own CONN_RSP handler adopt it:
 * it sets dcid@[chan+0x38] and auto-sends CONFIG_REQ, then runs config with the peer. */
typedef void *(*chan_create_fn)(void *conn, int type, unsigned int key);
/* sub_021109EC (seg0+0x109ec): the universal L2CAP frame sender, used for BOTH signaling and
 * connection-oriented data. ABI decoded from ksceBtSendL2capEchoRequestForTest's call site
 * (sub_021064B8): sub_021109EC(conn, cid, template, field0, field1, ...). The template is a
 * format string describing the L2CAP *payload* only — the engine frames the L2CAP basic header
 * itself from `cid` + the computed length. Template chars: '1'/'2'/'3'/'4' = an N-byte
 * little-endian scalar field, ' ' = separator, '#' = a variable-length blob consuming a
 * (ptr, len) pair from the arg list. Echo sends "112 #" (code,id,len,payload) on cid 1; for raw
 * RFCOMM data we send "#" (payload only) on the channel's dcid. */
typedef int (*l2cap_send_fn)(void *conn, int cid, const char *tmpl, const void *buf, int len);
static bt_lock_fn   g_bt_lock;
static bt_unlock_fn g_bt_unlock;
static conn_get_fn  g_conn_get;
static conn_req_fn  g_conn_req;
static config_req_fn g_config_req;
static chan_create_fn g_chan_create;
static l2cap_send_fn g_l2cap_send;
static void        *g_state_block;
static int          g_internals_ok;
static void        *g_conn;          /* connection obj of the device we sent CONN_REQ to */
static unsigned char *g_our_chan;    /* our adopted L2CAP channel object (from chan_create) */
static volatile int g_config_sent;   /* one-shot: send our CONFIG_REQ once per channel */

/* L2CAP channel state for driving RFCOMM on top. */
static volatile unsigned g_dcid;      /* the iPhone's CID for our RFCOMM channel (CONNECTION_RSP) */
static volatile int g_cfg_rsp_ok;     /* iPhone accepted our CONFIG_REQ (result 0) */
static volatile int g_cfg_req_seen;   /* iPhone sent its own CONFIG_REQ for our channel */
static volatile int g_sabm_sent;      /* one-shot: RFCOMM SABM on DLCI 0 sent */

/* Our chosen L2CAP source CID for the experimental RFCOMM channel. */
#define OUR_SCID 0x0080

/* A second L2CAP channel for an SDP client query (PSM 1) to discover the iAP2 RFCOMM channel.
 * The iPhone assigns iAP2 a dynamic RFCOMM server channel; the bridge finds it by a
 * ServiceSearchAttributeRequest for the 128-bit iAP2 UUID, reading the RFCOMM channel out of the
 * ProtocolDescriptorList. We do the same on-device and log the raw response to decode offline. */
#define SDP_SCID 0x0081
#define SDP_PSM  0x0001
static unsigned char *g_sdp_chan;
static volatile unsigned g_sdp_dcid;
static volatile int g_sdp_cfg_rsp_ok;
static volatile int g_sdp_cfg_req_seen;
static volatile int g_sdp_sent;

/* The iAP2 RFCOMM server channel, discovered via SDP = 1 on this iPhone. We are the RFCOMM session
 * initiator (we sent SABM on DLCI 0), so DLCI = channel<<1 | 0 = 2. Hardcoded for now; the SDP
 * query still runs and logs the channel each session, so we can switch to dynamic parsing later. */
#define IAP2_CHANNEL 1
#define IAP2_DLCI    (IAP2_CHANNEL << 1)
static volatile int g_dlc_sabm_sent;   /* one-shot: SABM on the iAP2 DLCI sent */
static volatile int g_msc_cmd_sent;    /* one-shot: our MSC command sent */
static volatile int g_msc_rsp_sent;    /* one-shot: our MSC response to the iPhone's MSC sent */

/* ---- M1: the kernel<->userspace byte pipe for the iAP2 DLC (DLCI 2) ----
 * Userspace (VitaPlay, running iap2c) reads RX bytes with vpbt_read and writes TX bytes with
 * vpbt_write; the kernel does the RFCOMM/credit framing. The iAP2 byte stream is transparent: RX
 * frame payloads are concatenated into g_rx and TX bytes are chopped into UIH frames (iap2c
 * re-frames on its side, so RFCOMM boundaries need not match iAP2 packet boundaries). */
static volatile int g_pipe_up;         /* iAP2 DLC is open + MSC done: byte pipe is usable */
static volatile int g_tx_credits;      /* RFCOMM credits the iPhone granted us (frames we may send) */
static volatile int g_rx_consumed;     /* iPhone frames received since our last credit grant */

#define RXR_SIZE 8192
static unsigned char g_rx[RXR_SIZE];   /* iAP2 payload from the iPhone (byte FIFO) */
static volatile unsigned g_rx_head;    /* producer: drain() */
static volatile unsigned g_rx_tail;    /* consumer: vpbt_read() */
static volatile unsigned g_rx_overflow;

/* A payload-only template for sub_021109EC: the whole arg blob becomes the L2CAP SDU. */
static const char TMPL_RAW_PAYLOAD[] = "#";

static void send_config_req(unsigned int dcid); /* defined below; called from drain() */
static void rfcomm_try_start(void);             /* send SABM once configured; called from drain() */
static void rfcomm_open_dlc(void);              /* send SABM on the iAP2 DLCI once the mux is up */
static void rfcomm_send_msc_command(void);      /* our MSC command for the iAP2 DLCI */
static void rfcomm_send_msc_response(unsigned dlci_octet, unsigned signals);
static void iap2_pipe_up(void);                 /* mark the DLC pipe usable + grant initial credits */
static void sdp_try_query(void);                /* send the SDP request once configured */

/* Lock-free-ish ring: the hook writes, the worker drains. Single producer (BT RX thread),
 * single consumer (worker), so a monotonic write index + barrier is enough. */
#define RING_SLOTS 32
#define CAP_BYTES 1024 /* hold a full iAP2 DLC frame (SDP/identification), not just signaling */
typedef struct {
    uint32_t conn;
    int32_t len;
    uint8_t data[CAP_BYTES];
} Pdu;
static Pdu g_ring[RING_SLOTS];
static volatile unsigned g_wr;
static volatile unsigned g_rd;
static volatile unsigned g_dropped;

/* Append iAP2 payload bytes to the RX FIFO (producer: drain). Drops on overflow. */
static void rx_push(const unsigned char *p, int n) {
    unsigned h = g_rx_head, t = g_rx_tail;
    for (int i = 0; i < n; i++) {
        if ((unsigned)(h - t) >= RXR_SIZE) { g_rx_overflow++; break; }
        g_rx[h % RXR_SIZE] = p[i];
        h++;
    }
    __sync_synchronize();
    g_rx_head = h;
}

static void log_line(const char *fmt, ...) {
    char line[512];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(line, sizeof(line) - 1, fmt, args);
    va_end(args);
    if (n < 0) return;
    if (n > (int)sizeof(line) - 2) n = sizeof(line) - 2;
    line[n++] = '\n';
    SceUID fd = ksceIoOpen(LOG_PATH, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0666);
    if (fd < 0) return;
    ksceIoWrite(fd, line, n);
    ksceIoClose(fd);
}

/* The hook. Runs in SceBt's RX thread context -> do the minimum: snapshot into the ring. */
static int hook_l2cap_sig(void *conn, const unsigned char *pdu, int len) {
    /* Only snapshot the channels we drive: L2CAP signaling (CID 1), our RFCOMM channel and our SDP
     * channel. This keeps the iPhone's high-volume PAN/mDNS traffic from flooding the ring. */
    unsigned cid = (pdu && len >= 8) ? (pdu[6] | (pdu[7] << 8)) : 0xFFFF;
    if (cid == 1 || cid == OUR_SCID || cid == SDP_SCID) {
        unsigned w = g_wr;
        if (w - g_rd >= RING_SLOTS) {
            g_dropped++;
        } else {
            Pdu *e = &g_ring[w % RING_SLOTS];
            e->conn = (uint32_t)(uintptr_t)conn;
            int n = len;
            if (n < 0) n = 0;
            if (n > CAP_BYTES) n = CAP_BYTES;
            for (int i = 0; i < n; i++) e->data[i] = pdu[i];
            e->len = len;
            __sync_synchronize();
            g_wr = w + 1;
        }
    }
    return TAI_CONTINUE(int, g_sig_ref, conn, pdu, len);
}

static const char *code_name(unsigned c) {
    switch (c) {
        case 0x01: return "COMMAND_REJECT";
        case 0x02: return "CONNECTION_REQ";
        case 0x03: return "CONNECTION_RSP";
        case 0x04: return "CONFIG_REQ";
        case 0x05: return "CONFIG_RSP";
        case 0x06: return "DISCONNECT_REQ";
        case 0x07: return "DISCONNECT_RSP";
        case 0x08: return "ECHO_REQ";
        case 0x09: return "ECHO_RSP";
        case 0x0A: return "INFO_REQ";
        case 0x0B: return "INFO_RSP";
        default: return "?";
    }
}

static void drain(void) {
    while (g_rd != g_wr) {
        Pdu *e = &g_ring[g_rd % RING_SLOTS];
        int n = e->len;
        if (n < 0) n = 0;
        if (n > CAP_BYTES) n = CAP_BYTES;
        /* The captured buffer is the raw incoming HCI ACL frame:
         *   [handle:2][acl_len:2][l2cap_len:2][cid:2][payload...]
         * For signaling (CID 1) the payload is [code][id][len:2][data]. */
        char hex[3 * 64 + 8];
        int o = 0;
        int hn = n > 64 ? 64 : n; /* log only a prefix; data frames can be large */
        for (int i = 0; i < hn; i++) o += snprintf(hex + o, sizeof(hex) - o, "%02x ", e->data[i]);
        if (n > hn) o += snprintf(hex + o, sizeof(hex) - o, "...(%d)", n);
        unsigned cid = n >= 8 ? (e->data[6] | (e->data[7] << 8)) : 0;
        unsigned l2len = n >= 6 ? (e->data[4] | (e->data[5] << 8)) : 0;
        if (cid == 1 && n >= 10) {
            unsigned code = e->data[8], id = e->data[9];
            if (code == 0x02 && n >= 16) { /* CONNECTION_REQ: psm, scid */
                unsigned psm = e->data[12] | (e->data[13] << 8);
                unsigned scid = e->data[14] | (e->data[15] << 8);
                log_line("L2CAP-IN sig=%s(0x%02x) id=%u PSM=0x%04x scid=0x%04x : %s",
                         code_name(code), code, id, psm, scid, hex);
            } else if (code == 0x03 && n >= 18) { /* CONNECTION_RSP: dcid, scid, result */
                unsigned dcid = e->data[12] | (e->data[13] << 8);
                unsigned scid = e->data[14] | (e->data[15] << 8);
                unsigned res = e->data[16] | (e->data[17] << 8);
                log_line("L2CAP-IN sig=%s(0x%02x) id=%u dcid=0x%04x scid=0x%04x result=%u : %s",
                         code_name(code), code, id, dcid, scid, res, hex);
                /* Channel accepted. SceBt's own CONN_RSP handler sets dcid and auto-configs our
                 * pre-created channel; we just capture the iPhone's dcid for our later data sends. */
                if (scid == OUR_SCID && res == 0) g_dcid = dcid;
                if (scid == SDP_SCID && res == 0) g_sdp_dcid = dcid;
                (void)send_config_req;
            } else if (code == 0x04 && n >= 14) { /* CONFIG_REQ: dcid (our scid), flags, options */
                unsigned d = e->data[12] | (e->data[13] << 8);
                log_line("L2CAP-IN sig=%s(0x%02x) id=%u dcid=0x%04x : %s",
                         code_name(code), code, id, d, hex);
                if (d == OUR_SCID) g_cfg_req_seen = 1;     /* iPhone configured our RFCOMM inbound */
                if (d == SDP_SCID) g_sdp_cfg_req_seen = 1;  /* ... and our SDP channel inbound */
            } else if (code == 0x05 && n >= 18) { /* CONFIG_RSP: scid, flags, result */
                unsigned scid = e->data[12] | (e->data[13] << 8);
                unsigned flags = e->data[14] | (e->data[15] << 8);
                unsigned res = e->data[16] | (e->data[17] << 8);
                log_line("L2CAP-IN sig=%s(0x%02x) id=%u scid=0x%04x flags=0x%04x result=%u : %s",
                         code_name(code), code, id, scid, flags, res, hex);
                if (scid == OUR_SCID && res == 0) g_cfg_rsp_ok = 1;     /* our RFCOMM config accepted */
                if (scid == SDP_SCID && res == 0) g_sdp_cfg_rsp_ok = 1;  /* our SDP config accepted */
            } else {
                log_line("L2CAP-IN sig=%s(0x%02x) id=%u : %s", code_name(code), code, id, hex);
            }
        } else if (cid == OUR_SCID && n >= 10) {
            /* Connection-oriented data on OUR RFCOMM channel = an RFCOMM frame from the iPhone.
             * Payload starts after the 8-byte [handle:2][acl_len:2][l2cap_len:2][cid:2] header:
             *   RFCOMM = [address:1][control:1][length:1-2][info...][fcs:1]. */
            unsigned addr = e->data[8], ctrl = e->data[9];
            unsigned dlci = addr >> 2;             /* DLCI = top 6 bits of the address octet */
            unsigned cb = ctrl & ~0x10;            /* strip the P/F bit for frame-type matching */
            const char *t = cb == 0x2f ? "SABM" : cb == 0x63 ? "UA" : cb == 0x0f ? "DM" :
                            cb == 0x43 ? "DISC" : cb == 0xef ? "UIH" : "?";
            log_line("RFCOMM-IN cid=0x%04x dlci=%u addr=0x%02x ctrl=0x%02x(%s) : %s",
                     cid, dlci, addr, ctrl, t, hex);
            if (cb == 0x63 && dlci == 0) {
                rfcomm_open_dlc();                                  /* mux up -> open the iAP2 DLC */
            } else if (cb == 0x63 && dlci == IAP2_DLCI) {
                log_line("  *** iAP2 RFCOMM DLC OPEN (dlci %u) ***", dlci);
                rfcomm_send_msc_command();                          /* begin the MSC handshake */
            } else if (cb == 0x0f && dlci == IAP2_DLCI) {
                log_line("  (RFCOMM DM: iPhone refused dlci %u -- may need PN first)", dlci);
            } else if (cb == 0xef && dlci == 0 && n >= 13) {
                /* Multiplexer control message on DLCI 0: info starts after addr+ctrl+len (3 bytes).
                 * MCC type octet 0xe3 = MSC command, 0xe1 = MSC response (type 0x38). */
                unsigned mcc = e->data[11];
                if (mcc == 0xe3 && n >= 15 && !g_msc_rsp_sent) {
                    g_msc_rsp_sent = 1;
                    log_line("  RFCOMM MSC command from iPhone (dlci-octet=0x%02x sig=0x%02x)",
                             e->data[13], e->data[14]);
                    rfcomm_send_msc_response(e->data[13], e->data[14]); /* ack it */
                    rfcomm_send_msc_command();                         /* and send ours if not yet */
                } else if (mcc == 0xe1) {
                    log_line("  RFCOMM MSC response from iPhone (our MSC acked) -- handshake done");
                } else {
                    log_line("  RFCOMM MCC type=0x%02x on dlci0", mcc);
                }
            } else if (cb == 0xef && dlci == IAP2_DLCI) {
                /* UIH data on the iAP2 DLC = the iAP2 byte stream from the iPhone. RFCOMM length may
                 * be 1 or 2 octets (EA bit of the first); with credit-based flow control (P/F bit
                 * set) a one-octet credit field follows the length. We strip the framing and hand
                 * the raw iAP2 bytes to userspace (iap2c) via the RX FIFO. */
                int pf = (ctrl & 0x10) != 0;
                int li = 10;                               /* first length octet */
                unsigned ilen;
                if (e->data[li] & 1) { ilen = e->data[li] >> 1; li += 1; }
                else { ilen = (e->data[li] >> 1) | (e->data[li + 1] << 7); li += 2; }
                if (pf) { g_tx_credits += e->data[li]; li += 1; } /* iPhone replenished our credits */
                int ioff = li;
                if ((unsigned)(ioff + (int)ilen) > (unsigned)n) ilen = (n > ioff) ? (n - ioff) : 0;
                log_line("  iAP2 RX dlci%u pf=%d datalen=%u txcred=%d : %s",
                         dlci, pf, ilen, g_tx_credits, hex);
                if (ilen) rx_push(&e->data[ioff], (int)ilen); /* -> userspace iap2c */
                g_rx_consumed++;                              /* iPhone spent one of our credits */
                iap2_pipe_up();                               /* first data -> pipe is usable */
            }
        } else if (cid == SDP_SCID) {
            /* SDP response on our SDP channel. Log the whole thing raw; decode the iAP2 RFCOMM
             * channel number offline from the ProtocolDescriptorList (UUID16 0x0003 then a uint8). */
            unsigned pdu = n >= 9 ? e->data[8] : 0;
            log_line("SDP-IN cid=0x%04x pdu=0x%02x l2len=%u : %s", cid, pdu, l2len, hex);
        } else {
            log_line("L2CAP-IN cid=0x%04x l2len=%u : %s", cid, l2len, hex);
        }
        rfcomm_try_start(); /* fire SABM once both RFCOMM config directions are done (one-shot) */
        sdp_try_query();    /* fire the SDP query once the SDP channel is configured (one-shot) */
        __sync_synchronize();
        g_rd++;
    }
}

static int worker(SceSize args, void *argp) {
    unsigned last_dropped = 0;
    while (!g_exiting) {
        drain();
        if (g_dropped != last_dropped) {
            log_line("(ring overflow: %u PDUs dropped)", g_dropped);
            last_dropped = g_dropped;
        }
        ksceKernelDelayThread(100 * 1000);
    }
    drain();
    return 0;
}

/* Bluetooth event callback, purely for context in the log (so PDUs line up with connect/disconnect). */
static void bt_cb(int r0, int r1, int r2, int r3) {
    (void)r0; (void)r1; (void)r2; (void)r3;
}

/* Open one outbound L2CAP channel to `psm` with our source CID `scid`: create a key-4 channel (so
 * it exists in SceBt's per-connection table), patch [+0x36]=scid (the key-5 lookup field the
 * CONN_RSP/CONFIG handlers match on) and clear [+8] (config options; create leaves 0x2a0 there,
 * which the CONFIG_REQ sender would mis-read as options), then send a CONNECTION_REQUEST. SceBt
 * then adopts the channel and runs the config handshake itself. Caller holds the BT lock. Returns
 * the channel object (so we can read its dcid later), or 0. */
static unsigned char *open_l2cap_channel(void *conn, unsigned psm, unsigned scid) {
    unsigned char chan[0x48] __attribute__((aligned(8)));
    unsigned char *ch = (unsigned char *)g_chan_create(conn, 0x14, scid);
    if (ch) {
        *(unsigned short *)(ch + 0x36) = (unsigned short)scid; /* key-5 lookup field */
        *(unsigned int *)(ch + 8) = 0;                         /* empty config options */
    }
    memset(chan, 0, sizeof(chan));
    *(unsigned short *)(chan + 0x34) = (unsigned short)psm;    /* target PSM */
    *(unsigned short *)(chan + 0x36) = (unsigned short)scid;   /* our source CID */
    int r = g_conn_req(conn, chan, 0, 0);
    log_line("  -> TX CONN_REQ PSM=0x%04x scid=0x%04x chan=%p rc=0x%x", psm, scid, ch, (unsigned)r);
    return ch;
}

/* On iPhone connect, open BOTH channels we need: the RFCOMM channel (PSM 0x0003) that carries the
 * RFCOMM multiplexer + the iAP2 DLC, and the SDP channel (PSM 0x0001) used to discover the iAP2
 * RFCOMM server-channel number. SceBt adopts + configures each; drain() then drives RFCOMM/SDP. */
static void try_rfcomm_connreq(unsigned int mac0, unsigned int mac1) {
    if (!g_internals_ok) return;
    if (g_bt_lock() != 0) {
        log_line("  open: BT lock busy, skipping");
        return;
    }
    void *conn = g_conn_get(g_state_block, 1, mac0, mac1);
    if (conn) {
        g_conn = conn;
        g_config_sent = 0;
        g_dcid = 0; g_cfg_rsp_ok = 0; g_cfg_req_seen = 0; g_sabm_sent = 0; g_our_chan = 0;
        g_dlc_sabm_sent = 0; g_msc_cmd_sent = 0; g_msc_rsp_sent = 0;
        g_pipe_up = 0; g_tx_credits = 0; g_rx_consumed = 0;
        g_rx_head = 0; g_rx_tail = 0; g_rx_overflow = 0;
        g_sdp_dcid = 0; g_sdp_cfg_rsp_ok = 0; g_sdp_cfg_req_seen = 0; g_sdp_sent = 0; g_sdp_chan = 0;
        g_our_chan = open_l2cap_channel(conn, 0x0003, OUR_SCID);
        g_sdp_chan = open_l2cap_channel(conn, SDP_PSM, SDP_SCID);
        log_line("  opened RFCOMM(scid 0x%04x) + SDP(scid 0x%04x) on conn=%p for %08x:%08x",
                 OUR_SCID, SDP_SCID, conn, mac0, mac1);
    } else {
        log_line("  open: conn_get NULL for %08x:%08x", mac0, mac1);
    }
    g_bt_unlock();
}

/* Step 2 of the channel open: once the iPhone accepts our CONN_REQ (CONNECTION_RSP result=0 for
 * OUR_SCID), send our L2CAP CONFIG_REQUEST with no options (accept defaults). dcid is the iPhone's
 * channel id from the CONNECTION_RSP. Called from the worker (drain) when it sees the response. */
static void send_config_req(unsigned int dcid) {
    static unsigned char chan[0x48] __attribute__((aligned(8)));
    if (!g_internals_ok || !g_conn) return;
    if (g_bt_lock() != 0) {
        log_line("  config: BT lock busy, skipping");
        return;
    }
    memset(chan, 0, sizeof(chan));
    *(unsigned short *)(chan + 0x36) = OUR_SCID;            /* our source CID */
    *(unsigned short *)(chan + 0x38) = (unsigned short)dcid; /* remote (iPhone) dcid */
    /* chan[8] left 0 => CONFIG_REQ carries no options (defaults). */
    int r = g_config_req(g_conn, chan);
    log_line("  -> TX L2CAP CONFIG_REQ dcid=0x%04x (no opts) rc=0x%x (watch for CONFIG_RSP/0x05)",
             dcid, (unsigned)r);
    g_bt_unlock();
}

/* ---- RFCOMM (TS 07.10) on top of the now-open L2CAP channel ---- */

/* RFCOMM FCS: CRC-8, polynomial x^8+x^2+x+1 (reversed 0xE0), init 0xFF, final ones-complement.
 * Computed over address+control+length for SABM/UA/DM/DISC; over address+control only for UIH.
 * Verified against the standard vectors: SABM(0) 03 3F 01 -> 1C, UA(0) 03 73 01 -> D7. */
static unsigned char rfcomm_fcs(const unsigned char *p, int n) {
    unsigned char f = 0xFF;
    for (int i = 0; i < n; i++) {
        f ^= p[i];
        for (int b = 0; b < 8; b++)
            f = (f & 1) ? (unsigned char)((f >> 1) ^ 0xE0) : (unsigned char)(f >> 1);
    }
    return (unsigned char)(0xFF ^ f);
}

/* Send a raw L2CAP data payload on an open channel, addressed to the iPhone's dcid, via the
 * universal frame sender with a payload-only template. Caller holds the BT lock. */
static int l2cap_data_send(unsigned dcid, const void *buf, int len) {
    if (!g_l2cap_send || !g_conn || !dcid) return -1;
    return g_l2cap_send(g_conn, (int)dcid, TMPL_RAW_PAYLOAD, buf, len);
}

/* Start the RFCOMM multiplexer: send SABM on DLCI 0 once the L2CAP channel is fully configured in
 * both directions. Frame = addr 0x03 (EA=1, C/R=1, DLCI=0), control 0x3F (SABM, P=1),
 * length 0x01 (EA=1, len=0), FCS over the 3 header bytes. The iPhone (RFCOMM server) should
 * answer with UA (control 0x73) on our cid — our RX hook will log it as RFCOMM-IN. One-shot. */
static void rfcomm_try_start(void) {
    if (g_sabm_sent || !g_cfg_rsp_ok || !g_cfg_req_seen) return;
    if (!g_internals_ok || !g_conn || !g_dcid) return;
    unsigned char sabm[4];
    sabm[0] = 0x03;
    sabm[1] = 0x3F;
    sabm[2] = 0x01;
    sabm[3] = rfcomm_fcs(sabm, 3);
    if (g_bt_lock() != 0) {
        log_line("  rfcomm: BT lock busy for SABM, will retry");
        return;
    }
    int r = l2cap_data_send(g_dcid, sabm, sizeof(sabm));
    g_bt_unlock();
    g_sabm_sent = 1;
    log_line("  -> TX RFCOMM SABM DLCI0 [%02x %02x %02x %02x] to dcid=0x%04x rc=0x%x (watch for UA/0x73)",
             sabm[0], sabm[1], sabm[2], sabm[3], g_dcid, (unsigned)r);
}

/* Open the iAP2 data channel: once the DLCI-0 multiplexer is up (we got its UA), send SABM on the
 * iAP2 DLCI. addr = EA | C/R(command from initiator) | DLCI<<2 = 0x0B for DLCI 2; the iPhone should
 * answer UA on the same DLCI. One-shot. If it answers DM instead, the channel wants PN first. */
static void rfcomm_open_dlc(void) {
    if (g_dlc_sabm_sent || !g_internals_ok || !g_conn || !g_dcid) return;
    unsigned char addr = (unsigned char)(0x01 | (1 << 1) | (IAP2_DLCI << 2));
    unsigned char f[4];
    f[0] = addr;
    f[1] = 0x3F;
    f[2] = 0x01;
    f[3] = rfcomm_fcs(f, 3);
    if (g_bt_lock() != 0) {
        log_line("  rfcomm: BT lock busy for DLC SABM, will retry");
        return;
    }
    int r = l2cap_data_send(g_dcid, f, sizeof(f));
    g_bt_unlock();
    g_dlc_sabm_sent = 1;
    log_line("  -> TX RFCOMM SABM DLCI%d [%02x %02x %02x %02x] to dcid=0x%04x rc=0x%x (watch for UA)",
             IAP2_DLCI, f[0], f[1], f[2], f[3], g_dcid, (unsigned)r);
}

/* Send a prebuilt RFCOMM frame (addr/ctrl/len/info/fcs already assembled) on our channel, under
 * the BT lock. Returns the sender's rc. */
static int rfcomm_send_frame(const unsigned char *f, int n) {
    if (g_bt_lock() != 0) {
        log_line("  rfcomm: BT lock busy for TX");
        return -1;
    }
    int r = l2cap_data_send(g_dcid, f, n);
    g_bt_unlock();
    return r;
}

/* RFCOMM MSC command for the iAP2 DLCI, as a UIH frame on DLCI 0. Frame: addr 0x03 (DLCI 0, command
 * from initiator), ctrl 0xEF (UIH), length 0x09 (4 info bytes), then the MCC: type 0xE3 (MSC cmd),
 * MCC length 0x05 (2 value bytes), value[0]=0x0B (DLCI-2 octet: EA|C/R|DLCI<<2), value[1]=0x8D
 * (V.24 signals: ready, not flow-controlled). FCS for UIH is over addr+ctrl only. One-shot. */
static void rfcomm_send_msc_command(void) {
    if (g_msc_cmd_sent) return;
    unsigned char f[8] = { 0x03, 0xEF, 0x09, 0xE3, 0x05, 0x0B, 0x8D, 0x00 };
    f[7] = rfcomm_fcs(f, 2);
    int r = rfcomm_send_frame(f, sizeof(f));
    g_msc_cmd_sent = 1;
    log_line("  -> TX RFCOMM MSC command (dlci %d) rc=0x%x", IAP2_DLCI, (unsigned)r);
}

/* RFCOMM MSC response (MCC type 0xE1), echoing the iPhone's DLCI octet and signal bits. */
static void rfcomm_send_msc_response(unsigned dlci_octet, unsigned signals) {
    unsigned char f[8] = { 0x03, 0xEF, 0x09, 0xE1, 0x05,
                           (unsigned char)dlci_octet, (unsigned char)signals, 0x00 };
    f[7] = rfcomm_fcs(f, 2);
    int r = rfcomm_send_frame(f, sizeof(f));
    log_line("  -> TX RFCOMM MSC response (dlci-octet=0x%02x sig=0x%02x) rc=0x%x",
             dlci_octet, signals, (unsigned)r);
}

/* Send a credit-only UIH frame on the iAP2 DLC (no data), granting the iPhone `grant` credits so it
 * may send us up to that many frames. addr 0x0B, ctrl 0xFF (UIH P/F=1), length 0 (EA=1), credit
 * octet, FCS over addr+ctrl. */
static void rfcomm_grant_credits(unsigned grant) {
    unsigned char f[5];
    f[0] = 0x0B;
    f[1] = 0xFF;
    f[2] = 0x01;                 /* length 0, EA=1 */
    f[3] = (unsigned char)grant;
    f[4] = rfcomm_fcs(f, 2);
    rfcomm_send_frame(f, sizeof(f));
    g_rx_consumed = 0;
}

/* The iAP2 DLC byte pipe becomes usable once the DLC is open and the first data/credit frame has
 * arrived. Grant the iPhone an initial batch of credits so it can send us its marker + SYN before
 * userspace writes anything, then mark the pipe up for vpbt_status. One-shot. */
static void iap2_pipe_up(void) {
    if (g_pipe_up || !g_dcid) return;
    g_pipe_up = 1;
    rfcomm_grant_credits(128);
    log_line("  *** iAP2 DLC byte pipe UP (granted 128 credits, txcred=%d) ***", g_tx_credits);
}

/* ---- M1: userspace-callable pipe (exported as syscalls; see exports.yml library VitaPlayBt) ----
 * vpbt_status: 1 when the iAP2 DLC pipe is usable, else 0 (negative on internal error).
 * vpbt_read:   copy up to max pending iAP2 RX bytes into the user buffer; returns the count (0 if
 *              none). vpbt_write: frame up to len user bytes as UIH data on the DLC; returns bytes
 *              accepted (0 if out of credits / not up). All pointers are userspace addresses. */
int vpbt_status(void) {
    return g_pipe_up ? 1 : 0;
}

int vpbt_read(void *ubuf, int max) {
    if (max <= 0) return 0;
    unsigned h = g_rx_head, t = g_rx_tail;
    unsigned avail = h - t;
    if (avail == 0) return 0;
    int n = (int)avail;
    if (n > max) n = max;
    unsigned char tmp[1024];
    if (n > (int)sizeof(tmp)) n = sizeof(tmp);
    for (int i = 0; i < n; i++) tmp[i] = g_rx[(t + i) % RXR_SIZE];
    if (ksceKernelCopyToUser(ubuf, tmp, n) < 0) return -1;
    __sync_synchronize();
    g_rx_tail = t + (unsigned)n;
    return n;
}

int vpbt_write(const void *ubuf, int len) {
    if (!g_pipe_up || !g_dcid || !g_l2cap_send) return -1;
    if (len <= 0) return 0;
    if (len > 4096) len = 4096;
    int done = 0;
    while (done < len) {
        if (g_tx_credits <= 0) break;            /* out of credits: let userspace retry after RX */
        int chunk = len - done;
        if (chunk > 120) chunk = 120;            /* keep a 1-octet RFCOMM length */
        unsigned char kbuf[120];
        if (ksceKernelCopyFromUser(kbuf, (const char *)ubuf + done, chunk) < 0)
            return done ? done : -1;
        /* UIH data frame on the DLC with CFC: addr, ctrl, length, credit grant, info, FCS. */
        unsigned char f[128];
        int grant = g_rx_consumed;
        if (grant > 200) grant = 200;
        g_rx_consumed -= grant;
        f[0] = 0x0B;
        f[1] = 0xFF;
        f[2] = (unsigned char)((chunk << 1) | 1);
        f[3] = (unsigned char)grant;
        for (int i = 0; i < chunk; i++) f[4 + i] = kbuf[i];
        f[4 + chunk] = rfcomm_fcs(f, 2);
        if (g_bt_lock() != 0) break;
        g_l2cap_send(g_conn, (int)g_dcid, TMPL_RAW_PAYLOAD, f, 4 + chunk + 1);
        g_bt_unlock();
        g_tx_credits--;
        done += chunk;
    }
    return done;
}

/* SDP ServiceSearchAttributeRequest for the 128-bit iAP2 UUID, asking for the
 * ProtocolDescriptorList (attribute 0x0004). Mirrors the bridge's sdp_query. Sent once the SDP
 * L2CAP channel is configured both directions. The response arrives on cid SDP_SCID and we log it
 * raw; the iAP2 RFCOMM channel is the uint8 after the RFCOMM UUID16 (0x0003) in the descriptor. */
static void sdp_try_query(void) {
    if (g_sdp_sent || !g_sdp_cfg_rsp_ok || !g_sdp_cfg_req_seen) return;
    if (!g_internals_ok || !g_conn || !g_sdp_dcid) return;
    /* iAP2 UUID 00000000-decafade-decadeaf-decacafe, big-endian on the wire. */
    static const unsigned char IAP2_UUID[16] = {
        0x00, 0x00, 0x00, 0x00, 0xde, 0xca, 0xfa, 0xde,
        0xde, 0xca, 0xde, 0xaf, 0xde, 0xca, 0xca, 0xfe };
    unsigned char req[32];
    int p = 0;
    /* SDP PDU header: [pdu=0x06 SSA_REQ][transaction:2][param_len:2] (param_len filled last). */
    req[p++] = 0x06;
    req[p++] = 0x00; req[p++] = 0x01;          /* transaction id = 1 */
    int lenpos = p; p += 2;                     /* param length placeholder */
    int params = p;
    /* ServiceSearchPattern: SEQ(17){ UUID128 }. */
    req[p++] = 0x35; req[p++] = 17; req[p++] = 0x1c;
    for (int i = 0; i < 16; i++) req[p++] = IAP2_UUID[i];
    /* MaximumAttributeByteCount = 0xFFFF. */
    req[p++] = 0xff; req[p++] = 0xff;
    /* AttributeIDList: SEQ(3){ uint16 0x0004 = ProtocolDescriptorList }. */
    req[p++] = 0x35; req[p++] = 3; req[p++] = 0x09; req[p++] = 0x00; req[p++] = 0x04;
    /* ContinuationState: one zero byte (none). */
    req[p++] = 0x00;
    int plen = p - params;
    req[lenpos] = (unsigned char)(plen >> 8);
    req[lenpos + 1] = (unsigned char)(plen & 0xff);
    if (g_bt_lock() != 0) {
        log_line("  sdp: BT lock busy for query, will retry");
        return;
    }
    int r = l2cap_data_send(g_sdp_dcid, req, p);
    g_bt_unlock();
    g_sdp_sent = 1;
    log_line("  -> TX SDP ServiceSearchAttributeReq (iAP2 UUID, %d bytes) to dcid=0x%04x rc=0x%x"
             " (watch for SDP-IN pdu=0x07)", p, g_sdp_dcid, (unsigned)r);
}

static int bt_event_thread(SceSize args, void *argp) {
    SceUID cb = ksceKernelCreateCallback("l2capprobe_bt", 0, (void *)bt_cb, NULL);
    if (cb < 0) return 0;
    ksceBtRegisterCallback(cb, 0, 0xFFFFFFFF, 0xFFFFFFFF);
    SceBtEvent ev;
    while (!g_exiting) {
        memset(&ev, 0, sizeof(ev));
        int got = ksceBtReadEvent(&ev, 1);
        if (got > 0) {
            log_line("BT-event id=0x%02x mac=%08x:%08x raw=%08x %08x %08x %08x",
                     ev.id, ev.mac0, ev.mac1,
                     *(uint32_t *)&ev.data[0], *(uint32_t *)&ev.data[4],
                     *(uint32_t *)&ev.data[8], *(uint32_t *)&ev.data[12]);
            /* TX round-trip test: when a device connects (event 0x05), send it an L2CAP echo
             * request via SceBt's own exported test function, and watch our RX hook catch the
             * ECHO_RSP (code 0x09). Proves we can inject L2CAP AND correlate the reply. */
            if (ev.id == 0x05 && (ev.mac0 || ev.mac1)) {
                static const unsigned char echo[8] = {'V', 'I', 'T', 'A', 'P', 'L', 'A', 'Y'};
                int r = ksceBtSendL2capEchoRequestForTest((int)ev.mac0, (int)ev.mac1,
                                                          (int)(uintptr_t)echo, (int)sizeof(echo));
                log_line("  -> TX echo to %08x:%08x : 0x%08x (watch for ECHO_RSP/0x09)",
                         ev.mac0, ev.mac1, (unsigned)r);
                /* Then the real experiment: a CONNECTION_REQUEST to the RFCOMM PSM. */
                try_rfcomm_connreq(ev.mac0, ev.mac1);
            }
        } else {
            ksceKernelDelayThreadCB(100 * 1000);
        }
    }
    ksceBtUnregisterCallback(cb);
    ksceKernelDeleteCallback(cb);
    return 0;
}

int module_start(SceSize argc, const void *args) {
    ksceIoMkdir("ux0:data/VitaPlay", 0777);
    log_line("---- l2capprobe loaded ----");
    log_line("bluetooth configuration: 0x%x", ksceBtGetConfiguration());

    tai_module_info_t info;
    info.size = sizeof(info);
    if (taiGetModuleInfoForKernel(KERNEL_PID, "SceBt", &info) < 0) {
        log_line("SceBt not found; nothing hooked");
        return SCE_KERNEL_START_SUCCESS;
    }
    log_line("SceBt modid=0x%08x nid=0x%08x", (unsigned)info.modid, (unsigned)info.module_nid);

    g_sig_hook = taiHookFunctionOffsetForKernel(KERNEL_PID, &g_sig_ref, info.modid,
                                                SCEBT_L2CAP_SIG_SEGMENT, SCEBT_L2CAP_SIG_OFFSET,
                                                1 /* thumb */, hook_l2cap_sig);
    log_line("hook sub_02106558 (seg%d+0x%x): 0x%08x", SCEBT_L2CAP_SIG_SEGMENT,
             SCEBT_L2CAP_SIG_OFFSET, (unsigned)g_sig_hook);
    if (g_sig_hook < 0) log_line("HOOK FAILED - offset wrong for this SceBt build?");

    /* Resolve SceBt internals from its segment bases (ASLR-safe). seg0=text, seg1=data. */
    SceKernelModuleInfo mi;
    memset(&mi, 0, sizeof(mi));
    mi.size = sizeof(mi);
    if (ksceKernelGetModuleInfo(KERNEL_PID, info.modid, &mi) >= 0) {
        uintptr_t seg0 = (uintptr_t)mi.segments[0].vaddr;
        uintptr_t seg1 = (uintptr_t)mi.segments[1].vaddr;
        g_bt_lock = (bt_lock_fn)((seg0 + 0x1b6b4) | 1);
        g_bt_unlock = (bt_unlock_fn)((seg0 + 0x1b7a0) | 1);
        g_conn_get = (conn_get_fn)((seg0 + 0x11420) | 1);
        g_conn_req = (conn_req_fn)((seg0 + 0x6422) | 1);
        g_config_req = (config_req_fn)((seg0 + 0x6384) | 1);
        g_chan_create = (chan_create_fn)((seg0 + 0x11544) | 1);
        g_l2cap_send = (l2cap_send_fn)((seg0 + 0x109ec) | 1);
        g_state_block = (void *)(seg1 + 0x10);
        g_internals_ok = 1;
        log_line("internals: seg0=0x%08x seg1=0x%08x state=%p conn_get=%p conn_req=%p l2cap_send=%p",
                 (unsigned)seg0, (unsigned)seg1, g_state_block, (void *)g_conn_get,
                 (void *)g_conn_req, (void *)g_l2cap_send);
    } else {
        log_line("ksceKernelGetModuleInfo failed; CONN_REQ experiment disabled");
    }

    g_thread = ksceKernelCreateThread("l2capprobe_log", worker, 0x3C, 0x2000, 0, 0x10000, 0);
    if (g_thread >= 0) ksceKernelStartThread(g_thread, 0, NULL);

    g_bt_thread = ksceKernelCreateThread("l2capprobe_bt", bt_event_thread, 0x3C, 0x2000, 0, 0x10000, 0);
    if (g_bt_thread >= 0) ksceKernelStartThread(g_bt_thread, 0, NULL);

    log_line("ready: pair+connect the iPhone and watch the L2CAP signaling");
    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args) {
    g_exiting = 1;
    if (g_sig_hook >= 0) {
        taiHookReleaseForKernel(g_sig_hook, g_sig_ref);
        g_sig_hook = -1;
    }
    if (g_thread >= 0) {
        ksceKernelWaitThreadEnd(g_thread, NULL, NULL);
        ksceKernelDeleteThread(g_thread);
        g_thread = -1;
    }
    if (g_bt_thread >= 0) {
        ksceKernelWaitThreadEnd(g_bt_thread, NULL, NULL);
        ksceKernelDeleteThread(g_bt_thread);
        g_bt_thread = -1;
    }
    log_line("---- l2capprobe unloaded ----");
    return SCE_KERNEL_STOP_SUCCESS;
}
