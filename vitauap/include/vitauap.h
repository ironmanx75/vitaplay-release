/*
 * vitauap — making the PS Vita its own Wi-Fi access point (uAP), from a kernel plugin.
 *
 * This header is a PORTING REFERENCE, not a linkable API: driving the AP is a technique applied to
 * SceWlanBt, not a set of exported functions. The reference implementation is plugin/softap.c (a
 * minimal SoftAP bring-up); the repo's apwait/ shows the "ordering flip" needed to run an app with
 * the AP up (see README.md). Firmware 3.65; segment base is ASLR-moved per boot, in-segment offsets
 * are stable — resolve the base at runtime via taiGetModuleInfoForKernel("SceWlanBt").
 *
 * STATUS: the receive half is proven (AP up, iPhone associates, uplink + DHCP work); DOWNLINK
 * (host -> client) is unsolved — see README.md and FINDINGS.md §8.
 */
#ifndef VITAUAP_H
#define VITAUAP_H

/* --- SceWlanBt seg0 offsets (FW 3.65) --- */
#define WLANUAP_OFF_ALLOC   0x2954  /* sub_02954(adapter,size) -> cmd node; node[8]=payload(cmdbuf+0xc) */
#define WLANUAP_OFF_ENQUEUE 0x2db4  /* sub_02db4(adapter,node,u16 opcode,len): fills header + queues   */
#define WLANUAP_OFF_RESP    0x1cd4  /* sub_01cd4(adapter,msg,...): resp/event; type@+2 code@+4 result@+0xa */

/* --- Marvell/mwifiex uAP host-command IDs (response = cmd | 0x8000) --- */
#define WLANUAP_CMD_SYS_CONFIG 0x00b0
#define WLANUAP_CMD_BSS_START  0x00b1
#define WLANUAP_CMD_BSS_STOP   0x00b2
#define WLANUAP_ACT_GEN_SET    0x0001

/* --- uAP TLV type IDs (PROPRIETARY_TLV_BASE_ID = 0x0100) --- */
#define WLANUAP_TLV_SSID         0x0000
#define WLANUAP_TLV_MAC_ADDRESS  0x012b
#define WLANUAP_TLV_CHANNELBAND  0x012a  /* u8 band_config (0=2.4G) + u8 channel */
#define WLANUAP_TLV_BCAST_SSID   0x0130  /* u8: 1 = broadcast SSID on */
#define WLANUAP_TLV_ENCRY_PROTO  0x0140  /* le16; 0x01 = PROTOCOL_NO_SECURITY (open) */

/*
 * THE KEY TRICK: the station driver's enqueue force-zeroes cmdbuf[9] (the seq_num high byte =
 * bss_num | bss_type<<4), so every command targets the STATION engine. uAP commands must target the
 * uAP engine: re-stamp cmdbuf[9] = 0x10 (bss_num=0, bss_type=1=UAP) RIGHT AFTER enqueue returns and
 * BEFORE the send-worker DMAs the buffer (a tight spin wins the race deterministically). cmdbuf is
 * at node[4]. Without this, SYS_CONFIG returns result=1; with it, result=0 and the AP beacons.
 */
#define WLANUAP_BSS9_UAP 0x10

/*
 * Minimal bring-up (see plugin/softap.c):
 *   1) SYS_CONFIG(SET) with TLVs {SSID, [MAC], CHANNELBAND, [BCAST_SSID], ENCRY_PROTO=open}, bss9=UAP
 *   2) BSS_START (empty body), bss9=UAP
 * Then the SSID beacons and clients associate (the firmware does auth/assoc on its own; it raises
 * mwifiex uAP events through the response handler: 0x002d STA_ASSOC, 0x002c/0x0043/0x0044 BSS * ).
 *
 * To actually run an app while the AP is up, you MUST launch the app FIRST and raise the AP under it
 * (the "ordering flip"); launching an app into an already-up AP kernel-panics on 3.65. Interface
 * config (assign an IP, bring wlan0 up) is done from an UNSAFE-self userland app via
 * sceNetSyscallIoctl on a sceNetSyscallSocket descriptor (FreeBSD SIOCSIFADDR/NETMASK/FLAGS ABI).
 */

#endif /* VITAUAP_H */
