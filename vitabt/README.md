# vitabt — on-device Bluetooth iAP2 for the PS Vita

A small, reusable library that lets a **PS Vita be the Bluetooth RFCOMM client to an iPhone's iAP2
service** — the thing the Vita's own `SceBt` will not do on its own. It is the Bluetooth bootstrap
from [VitaPlay](../vitaplay) carved out so other homebrew can use it.

With this, a Vita app can pair an iPhone and open a live, bidirectional **iAP2 byte pipe** to it, on
the Vita, with no bridge PC or ESP32. That pipe is what wireless CarPlay's bring-up runs over
(identification, MFi auth, the Wi-Fi handoff), but the pipe itself is protocol-agnostic iAP2 — use
it for whatever iAP2 accessory role you like.

For the full story of how this was reverse-engineered — why it looked impossible and the technique
that cracked it — read [`../FINDINGS.md`](../FINDINGS.md). This README is the integration guide.

> **Related:** [`../vitauap/`](../vitauap/) is a sibling library for the *other* radio — driving the
> Vita's **Wi-Fi into access-point (uAP) mode** so a phone can join the Vita with no router. It's the
> router-free counterpart to this Bluetooth bootstrap (research-stage; see `../FINDINGS.md` §8).

> **Firmware:** the kernel plugin's reverse-engineered offsets are for **firmware 3.65**. On other
> firmware you must re-derive the handful of `SceBt` functions (see FINDINGS.md §4 and the comments
> in `plugin/vitaplaybt.c`). Everything above the plugin (the API and `iap2c`) is
> firmware-independent.
>
> **This is experimental, as-is, GPL-3.0.** No warranty, no support promise. Not affiliated with
> Apple or Sony. CarPlay and iAP2 are Apple's.

## What's in the box

| Path | What |
|---|---|
| `plugin/` | The `vitaplaybt` taiHEN **kernel plugin**: hand-drives SceBt's L2CAP to open the RFCOMM iAP2 channel, speaks RFCOMM (TS 07.10) + a minimal SDP client, and exposes the iAP2 DLC as a byte pipe through the `VitaPlayBt` syscalls. Builds `vitaplaybt.skprx` + the userspace stub. |
| `include/vitaplaybt.h` | The **public userspace API**: `vpbt_status` / `vpbt_read` / `vpbt_write`, fully documented. |
| `iap2c/` | An **iAP2 link-layer** state machine (C port of the iAP2 link engine). Optional — use it to speak iAP2 over the pipe, or bring your own. |
| `examples/minimal.c` | The smallest useful driver: waits for a phone, runs `iap2c` over the pipe to NORMAL, logs the iAP2 control messages. |

## How it fits together

```
   your app  (userspace)
      |  vpbt_read / vpbt_write / vpbt_status   <-- include/vitaplaybt.h
      v
  vitaplaybt.skprx  (kernel, boot-loaded)
      |  hand-driven L2CAP -> RFCOMM -> iAP2 DLC
      v
   SceBt  ->  Bluetooth  ->  iPhone's iAP2 service
```

The plugin does the hard, firmware-specific part (open the channel, RFCOMM, credits) and hands you
a clean byte pipe. Your app runs the iAP2 protocol on top — the `iap2c` link layer handles the iAP2
link framing, and you handle the CSM messages (identification, MFi, etc.). `examples/minimal.c`
shows the loop.

## Build

Needs VitaSDK at `$VITASDK` (or `~/vitasdk`) with the `taihen` package.

```sh
make -C plugin     # -> plugin/vitaplaybt.skprx and plugin/stubs/libvitaplaybt_stub[_weak].a
make -C iap2c      # -> the iAP2 link-layer static lib (optional)
```

Then in your app:

- add `include/` (and `iap2c/` if you use it) to your include path,
- link the **weak** stub: `-Lplugin/stubs -lvitaplaybt_stub_weak`,
- pack `vitaplaybt.skprx` into your VPK.

## Install / boot-load the plugin (important)

The plugin must be **resident before your app starts**. A userspace app cannot load a kernel module
and then import syscalls from it — the imports are bound at app-load time, before the module exists,
so the first call traps (seen in the wild as a `C2-12828` crash). So load it at boot via taiHEN.

1. Enable **Unsafe Homebrew** (HENkaku settings) — it's a kernel module.
2. Put `vitaplaybt.skprx` somewhere stable (e.g. your app's data dir, or packed in your VPK at
   `ux0:app/<TITLEID>/vitaplaybt.skprx`).
3. Add it to `ux0:tai/config.txt` under `*KERNEL`, then reboot:
   ```
   *KERNEL
   ux0:app/<TITLEID>/vitaplaybt.skprx
   ```
4. Link the **weak** stub so your app still loads when the plugin is absent; `vpbt_status()` just
   reports "down" in that case.

## Using the pipe

The API is three non-blocking calls (full docs in `include/vitaplaybt.h`):

```c
int vpbt_status(void);                 /* 1 when the iAP2 pipe is usable, else 0 */
int vpbt_read (void *buf, int max);    /* inbound iAP2 bytes (iPhone -> Vita); 0 if none */
int vpbt_write(const void *buf, int len); /* outbound iAP2 bytes (Vita -> iPhone) */
```

Lifecycle: poll `vpbt_status()`. On `0 -> 1`, an iPhone is connected and the iAP2 DLC is up — start
your iAP2 link. Pump `vpbt_read` into the link, pump the link's output to `vpbt_write`. On `1 -> 0`,
the phone dropped the channel — tear down and wait for the next connection. See `examples/minimal.c`.

The bytes are transparent iAP2 **link** data (RFCOMM framing stripped). To speak iAP2 you still need
the link layer (`iap2c`) plus the CSM messages for your accessory role. For a complete, working
accessory — identification, MFi authentication and the wireless CarPlay handoff, over this exact
pipe — read [`../vitaplay/src/btboot.c`](../vitaplay/src/btboot.c) and
[`../vitaplay/src/iap2_ident.c`](../vitaplay/src/iap2_ident.c).

## Prerequisites the plugin assumes

- **Pairing an iPhone** needs SceBt's "allow unsupported device" patch (the well-known VitaControl
  trick; set the device flag bits `0x11000`). Without it SceBt refuses the pairing. The plugin does
  not do this for you — pair the iPhone first (Settings → Bluetooth) with that patch in place.
- The iPhone must be **connected** (on its Bluetooth screen / actively connected) for the plugin to
  find its connection object and open the channel.

## License and keys

GPL-3.0, matching the PlayPort / DiPlay / xcertplay lineage this is derived from. If you build an
MFi accessory on top of this, the MFi accessory identity (private key + certificate) is **yours to
supply and must never be committed or redistributed**.
