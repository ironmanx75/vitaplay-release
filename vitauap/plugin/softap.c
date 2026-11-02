/*
 * softap: bring the Vita's Wi-Fi up as an access point (uAP) by driving SceWlanBt's command path.
 *
 * Background: the wlanuap probe proved the Robin firmware answers UAP_SYS_CONFIG (0x00b0 -> 0x80b0),
 * i.e. the chip firmware has a real AP-mode handler. This plugin takes the next step: send the
 * canonical minimal uAP bring-up sequence and watch the firmware's result status.
 *
 * Sequence (standard Marvell/mwifiex uAP):
 *   1. UAP_SYS_CONFIG (0x00b0), action=SET, with TLVs: SSID, BCAST_SSID, CHANNELBANDLIST,
 *      ENCRY_PROTOCOL=NO_SECURITY (open network for this first milestone).
 *   2. UAP_BSS_START (0x00b1), empty body.
 * We log every response's command code (msg+4) AND result status word (msg+0xa) so we can see
 * whether each step actually SUCCEEDED (result==0), not just that it was recognized.
 *
 * Wire framing (SceWlanBt cmd buffer == Marvell SDIO): len@+0, type@+2=1(CMD), command@+4,
 * size@+6, seq@+8, result@+0xa, body@+0xc. We write the body at node's payload (cmdbuf+0xc) and
 * call enqueue(adapter,node,opcode,bodylen); the driver fills the header.
 *
 * Command path (SceWlanBt seg0, FW 3.65; base ASLR-moved, offsets stable):
 *   sub_02954(adapter,size)            -> cmd node; node[8] = payload ptr (cmdbuf+0xc)
 *   sub_02db4(adapter,node,opcode,len) -> fills header + queues
 *   sub_01cd4(adapter,msg,len,...)     -> firmware-response handler; code@msg+4, result@msg+0xa
 *
 * SAFETY: this takes the Wi-Fi interface into AP mode. Run with Wi-Fi ENABLED but NOT connected to
 * any network. Do not join a network while it runs. A reboot restores normal Wi-Fi. One-shot.
 */
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/io/stat.h>
#include <stdarg.h>
#include <stdint.h>
#include <taihen.h>

#define DIR "ux0:data/VitaPlay"
#define LOG DIR "/softap.log"

#define OFF_ALLOC   0x2954
#define OFF_ENQUEUE 0x2db4
#define OFF_RESP    0x1cd4

/* mwifiex host command IDs */
#define CMD_UAP_SYS_CONFIG 0x00b0
#define CMD_UAP_BSS_START  0x00b1
#define CMD_UAP_BSS_STOP   0x00b2

#define ACT_GEN_SET 0x0001

/* uAP TLV type IDs (PROPRIETARY_TLV_BASE_ID = 0x0100) */
#define TLV_UAP_MAC_ADDRESS 0x012b
#define TLV_UAP_SSID        0x0000
#define TLV_UAP_BCAST_SSID  0x0130
#define TLV_CHANNELBANDLIST 0x012a
#define TLV_UAP_ENCRY_PROTO 0x0140

/* encryption protocol bitmask */
#define PROTOCOL_NO_SECURITY 0x01

/* ---- AP parameters for this milestone (open network) ---- */
#define AP_SSID    "VitaPlay-CP"
#define AP_SSID_LEN 11
#define AP_CHANNEL  6
#define AP_BAND     0x00   /* 2.4 GHz */

typedef void *(*alloc_fn)(void *adapter, int size);
typedef int (*enqueue_fn)(void *adapter, void *node, int opcode, int len);

static alloc_fn g_alloc;
static enqueue_fn g_enqueue;
static tai_hook_ref_t g_enq_ref, g_resp_ref;
static SceUID g_enq_hook = -1, g_resp_hook = -1;
static SceUID g_worker = -1;
static volatile void *g_adapter;
static volatile int g_exiting;

/* response ring: packs code (hi 16) | result (lo 16) */
static volatile unsigned g_ring[128];
static volatile unsigned g_rw, g_rr;
static volatile unsigned g_enq_count;

static void logln(const char *fmt, ...) {
    char line[224];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(line, sizeof(line) - 1, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof(line) - 2) n = (int)sizeof(line) - 2;
    line[n++] = '\n';
    SceUID fd = ksceIoOpen(LOG, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0666);
    if (fd < 0) return;
    ksceIoWrite(fd, line, n);
    ksceIoClose(fd);
}

static int hk_enqueue(void *adapter, void *node, int opcode, int len) {
    if (!g_adapter) g_adapter = adapter;
    g_enq_count++;
    return TAI_CONTINUE(int, g_enq_ref, adapter, node, opcode, len);
}

static int hk_resp(void *adapter, void *msg, int len, int a3) {
    if (msg) {
        unsigned code = *(unsigned short *)((char *)msg + 4);
        unsigned res  = *(unsigned short *)((char *)msg + 0xa);
        unsigned w = g_rw;
        g_ring[w & 127] = (code << 16) | res;
        g_rw = w + 1;
    }
    return TAI_CONTINUE(int, g_resp_ref, adapter, msg, len, a3);
}

/* Append a TLV (type,len + payload) to buf at *off; returns pointer to the value area. */
static unsigned char *put_tlv(unsigned char *buf, int *off, unsigned type, unsigned vlen) {
    buf[*off + 0] = type & 0xff;
    buf[*off + 1] = (type >> 8) & 0xff;
    buf[*off + 2] = vlen & 0xff;
    buf[*off + 3] = (vlen >> 8) & 0xff;
    unsigned char *v = buf + *off + 4;
    *off += 4 + (int)vlen;
    return v;
}

/*
 * Send one command. The driver's enqueue (sub_02db4) force-zeroes cmdbuf[9] (the seq_num high
 * byte = bss_num/bss_type), so it always addresses the STA engine. For uAP commands we must
 * re-stamp cmdbuf[9] = (bss_num) | (bss_type<<4) AFTER enqueue returns, before the send-worker
 * DMAs the buffer. We do it with no blocking call in between and a tight re-write spin to cover
 * the window. bss9=0x00 -> STA, 0x10 -> uAP (bss_type=1). Returns the enqueue rc.
 */
static int send_cmd(int opcode, const unsigned char *body, int bodylen, unsigned bss9) {
    void *node = g_alloc((void *)g_adapter, bodylen > 8 ? bodylen : 8);
    if (!node) { logln("  alloc failed for cmd 0x%04x", opcode); return -1; }
    unsigned char *cmdbuf  = *(unsigned char **)((char *)node + 4);
    unsigned char *payload = *(unsigned char **)((char *)node + 8);
    if (!payload) { logln("  null payload for cmd 0x%04x", opcode); return -1; }
    for (int i = 0; i < bodylen; i++) payload[i] = body ? body[i] : 0;
    int rc = g_enqueue((void *)g_adapter, node, opcode, bodylen);
    if (bss9 && cmdbuf) {
        for (int i = 0; i < 2000; i++) cmdbuf[9] = (unsigned char)bss9; /* win the race to the DMA */
        logln("  (stamped bss_type: cmdbuf[9]=0x%02x readback=0x%02x)", bss9, cmdbuf[9]);
    }
    return rc;
}

/* Drain the response ring for `ms` ms. Returns the result status of want_code if seen (>=0),
 * else -1. If verbose, logs EVERY response code (to catch association/event traffic when a
 * client joins); otherwise logs only want_code and uAP-range (0xb0..0xb2) codes. */
static int watch(int ms, unsigned want_code, int verbose) {
    int result = -1;
    for (int t = 0; t < ms / 100 && !g_exiting; t++) {
        while (g_rr != g_rw) {
            unsigned e = g_ring[g_rr & 127]; g_rr++;
            unsigned code = e >> 16, res = e & 0xffff;
            if (code == want_code) {
                result = (int)res;
                logln("  <= resp 0x%04x result=%u  %s", code, res,
                      res == 0 ? "*** SUCCESS ***" : "(nonzero = firmware rejected)");
            } else if (verbose) {
                logln("  <= resp 0x%04x result=%u", code, res);
            } else if ((code & 0xff) == 0xb0 || (code & 0xff) == 0xb1 || (code & 0xff) == 0xb2) {
                logln("  <= resp 0x%04x result=%u (uAP)", code, res);
            }
        }
        ksceKernelDelayThread(100000);
    }
    return result;
}

#define BSS9_UAP 0x10  /* seq_num high byte: bss_num=0, bss_type=1 (UAP) */

/* Build a UAP_SYS_CONFIG SET body. variant 0 = full (MAC+SSID+BCAST+CHAN+ENCRY open),
 * variant 1 = minimal (SSID+ENCRY open). Returns body length. */
static int build_set(unsigned char *body, int variant) {
    int off = 0;
    body[off++] = ACT_GEN_SET & 0xff;
    body[off++] = (ACT_GEN_SET >> 8) & 0xff;
    if (variant == 0) {
        unsigned char *v = put_tlv(body, &off, TLV_UAP_MAC_ADDRESS, 6);
        static const unsigned char mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
        for (int i = 0; i < 6; i++) v[i] = mac[i];
    }
    {
        unsigned char *v = put_tlv(body, &off, TLV_UAP_SSID, AP_SSID_LEN);
        const char *s = AP_SSID;
        for (int i = 0; i < AP_SSID_LEN; i++) v[i] = (unsigned char)s[i];
    }
    if (variant == 0) {
        unsigned char *v = put_tlv(body, &off, TLV_UAP_BCAST_SSID, 1);
        v[0] = 1;
        v = put_tlv(body, &off, TLV_CHANNELBANDLIST, 2);
        v[0] = AP_BAND; v[1] = AP_CHANNEL;
    }
    {
        unsigned char *v = put_tlv(body, &off, TLV_UAP_ENCRY_PROTO, 2);
        v[0] = PROTOCOL_NO_SECURITY; v[1] = 0;
    }
    return off;
}

/* Try one SYS_CONFIG variant with uAP bss_type, log result. Returns 0 on success (result==0). */
static int try_config(int variant) {
    unsigned char body[256];
    int off = build_set(body, variant);
    logln("=> UAP_SYS_CONFIG (SET) variant=%d (%s) body=%d bytes, bss_type=UAP",
          variant, variant == 0 ? "full+MAC+chan" : "minimal ssid+open", off);
    int rc = send_cmd(CMD_UAP_SYS_CONFIG, body, off, BSS9_UAP);
    logln("   enqueue rc=%d; watching 5s for 0x80b0 ...", rc);
    int res = watch(5000, 0x80b0, 0);
    if (res < 0) { logln("   (no 0x80b0 seen)"); return -1; }
    return res == 0 ? 0 : 1;
}

static int worker(SceSize argc, void *argp) {
    (void)argc; (void)argp;
    /* Wait up to ~60s for a live Wi-Fi command so we capture a valid adapter. */
    for (int i = 0; i < 600 && !g_adapter && !g_exiting; i++) ksceKernelDelayThread(100000);
    if (!g_adapter) { logln("no adapter captured (enable Wi-Fi so the driver issues a command)"); return 0; }
    logln("adapter=%p after %u enqueues; waiting 10s for Wi-Fi to settle (do NOT join a network)",
          (void *)g_adapter, g_enq_count);
    for (int i = 0; i < 100 && !g_exiting; i++) ksceKernelDelayThread(100000);

    /* ---- Step 1: UAP_SYS_CONFIG (SET) with uAP bss_type. Try full, then minimal. ---- */
    int cfg = try_config(0);              /* full: MAC + SSID + BCAST + CHAN + open */
    if (cfg != 0) cfg = try_config(1);    /* fallback: minimal SSID + open */

    if (cfg != 0) {
        logln("---- SYS_CONFIG still not result=0; BSS_START skipped. See result codes above. ----");
        logln("---- (watching 20s for stray responses) ----");
        watch(20000, 0xffff, 1);
        logln("---- softap window done (reboot to restore normal Wi-Fi) ----");
        return 0;
    }

    /* ---- Step 2: UAP_BSS_START (empty body, uAP bss_type) ---- */
    logln("=> UAP_BSS_START (bss_type=UAP)");
    int rc = send_cmd(CMD_UAP_BSS_START, NULL, 0, BSS9_UAP);
    logln("   enqueue rc=%d; watching 5s for 0x80b1 ...", rc);
    int startres = watch(5000, 0x80b1, 0);
    if (startres < 0) logln("   (no 0x80b1 seen)");
    else if (startres == 0) logln("   *** BSS_START result=0 — AP SHOULD BE BEACONING '%s' ***", AP_SSID);

    logln("==================================================================");
    logln(">> NOW: on your phone, TAP '%s' and try to join (open, no password).", AP_SSID);
    logln(">> Watching 180s and logging EVERY firmware response (assoc traffic).");
    logln("==================================================================");
    watch(180000, 0xffff, 1);
    logln("---- softap window done (reboot to restore normal Wi-Fi) ----");
    return 0;
}

int module_start(SceSize argc, const void *args) {
    (void)argc; (void)args;
    ksceIoMkdir(DIR, 0777);
    logln("---- softap loaded ----");

    tai_module_info_t info;
    info.size = sizeof(info);
    if (taiGetModuleInfoForKernel(KERNEL_PID, "SceWlanBt", &info) < 0) {
        logln("SceWlanBt not found");
        return SCE_KERNEL_START_SUCCESS;
    }
    SceKernelModuleInfo mi;
    memset(&mi, 0, sizeof(mi));
    mi.size = sizeof(mi);
    if (ksceKernelGetModuleInfo(KERNEL_PID, info.modid, &mi) < 0) {
        logln("GetModuleInfo failed");
        return SCE_KERNEL_START_SUCCESS;
    }
    uintptr_t seg0 = (uintptr_t)mi.segments[0].vaddr;
    g_alloc = (alloc_fn)((seg0 + OFF_ALLOC) | 1);
    g_enqueue = (enqueue_fn)((seg0 + OFF_ENQUEUE) | 1);
    logln("SceWlanBt modid=0x%08x seg0=0x%08x alloc=%p enqueue=%p",
          (unsigned)info.modid, (unsigned)seg0, (void *)g_alloc, (void *)g_enqueue);

    g_enq_hook = taiHookFunctionOffsetForKernel(KERNEL_PID, &g_enq_ref, info.modid, 0, OFF_ENQUEUE, 1, hk_enqueue);
    g_resp_hook = taiHookFunctionOffsetForKernel(KERNEL_PID, &g_resp_ref, info.modid, 0, OFF_RESP, 1, hk_resp);
    logln("hooks: enqueue=0x%08x resp=0x%08x", (unsigned)g_enq_hook, (unsigned)g_resp_hook);

    g_worker = ksceKernelCreateThread("softap", worker, 0x40, 0x2000, 0, 0x10000, 0);
    if (g_worker >= 0) ksceKernelStartThread(g_worker, 0, NULL);
    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args) {
    (void)argc; (void)args;
    g_exiting = 1;
    if (g_enq_hook >= 0) taiHookReleaseForKernel(g_enq_hook, g_enq_ref);
    if (g_resp_hook >= 0) taiHookReleaseForKernel(g_resp_hook, g_resp_ref);
    ksceKernelDelayThread(200000);
    return SCE_KERNEL_STOP_SUCCESS;
}
