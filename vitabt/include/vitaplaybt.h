/*
 * vitabt — on-device Bluetooth iAP2 for the PS Vita.
 *
 * Public userspace API for the `vitaplaybt` kernel plugin. The plugin opens an RFCOMM iAP2 channel
 * to a connected iPhone (hand-driving SceBt's L2CAP, since SceBt itself never dials out) and
 * exposes that channel as a transparent byte pipe through three syscalls. Your app reads and writes
 * raw iAP2 link bytes; the kernel handles the RFCOMM/credit framing underneath.
 *
 * See README.md for how it works, the plugin lifecycle, and a worked example. GPL-3.0.
 *
 * LINKING: build plugin/ to get stubs/libvitaplaybt_stub_weak.a and link that
 *   (-Lplugin/stubs -lvitaplaybt_stub_weak). The WEAK stub is important: the plugin is loaded at
 *   boot via taiHEN config.txt, not by your app, so without it a build that references these
 *   symbols would fail to load when the plugin is absent. With the weak stub, the imports resolve
 *   to safe stubs and vpbt_status() simply reports "down" until the plugin is resident.
 *
 * THREADING: the three calls are safe to call from one userspace thread (a poll loop). They do not
 *   block. Do not call them concurrently from multiple threads.
 */
#ifndef VITAPLAYBT_H
#define VITAPLAYBT_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Is the iAP2 byte pipe usable right now?
 *
 * Returns 1 once the plugin has, for the currently connected iPhone, opened the L2CAP channel to
 * the RFCOMM PSM, brought up the iAP2 DLC and completed the modem-status (MSC) handshake — i.e. the
 * pipe can carry iAP2 bytes. Returns 0 while no iPhone is connected or the DLC is not yet up, and a
 * negative value on an internal plugin error. Returns 0 when the plugin is not resident (weak stub).
 *
 * Poll this. On a 0 -> 1 transition, (re)start your iAP2 link. On a 1 -> 0 transition, the iPhone
 * dropped the channel; tear your link down and wait for the next connection.
 */
int vpbt_status(void);

/*
 * Read pending inbound iAP2 bytes (iPhone -> Vita) into ubuf, up to max bytes.
 *
 * Returns the number of bytes copied, or 0 when nothing is pending. The byte stream is transparent
 * iAP2 link data (the RFCOMM framing has been stripped); feed it straight into your iAP2 link layer
 * (e.g. iap2c's iap2_link_feed). Call repeatedly until it returns 0 to drain all available data.
 * A single call may return less than a full iAP2 frame; the link layer reassembles.
 */
int vpbt_read(void *ubuf, int max);

/*
 * Write outbound iAP2 bytes (Vita -> iPhone) from ubuf, len bytes.
 *
 * The kernel frames them as RFCOMM UIH data on the iAP2 DLC (splitting into credit-sized frames as
 * needed). Returns the number of bytes accepted, or -1 if the pipe is not up. Pass whatever your
 * iAP2 link layer produces (e.g. the output of iap2_link_output).
 */
int vpbt_write(const void *ubuf, int len);

#ifdef __cplusplus
}
#endif

#endif /* VITAPLAYBT_H */
