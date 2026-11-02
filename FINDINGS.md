# On-device wireless CarPlay on the PS Vita — findings

This is a write-up of how we got a **PS Vita (firmware 3.65) to run the entire wireless CarPlay
bring-up by itself**, with no second device bridging Bluetooth. An iPhone pairs to the Vita, the
Vita does the Bluetooth iAP2 bootstrap and the Wi-Fi handoff on its own, and the phone then streams
CarPlay (video, touch, Siri, now-playing) to the Vita over Wi-Fi.

It is written for the Vita / CarPlay homebrew community: here is what we found and how it works. The
code is in this repo. **It is yours to do with what you want** — as-is, no warranty, no maintenance
promise. Not affiliated with or endorsed by Apple or Sony. CarPlay is a trademark of Apple Inc.

> **Status:** everything up to and including the full CarPlay control session runs on the Vita with
> no bridge. **Audio output is the one piece not yet working** — see "What doesn't work yet" below.

---

## 1. Why this was supposed to be impossible

Wireless CarPlay always begins over **Bluetooth**. The phone and the accessory exchange **iAP2**
messages over an **RFCOMM** channel; the accessory authenticates (MFi), hands the phone Wi-Fi
credentials and the receiver's address, and only then does the phone connect to the AirPlay service
over Wi-Fi and start streaming.

The catch: the accessory has to be the **RFCOMM client** — it dials *out* to the iPhone's iAP2
service. The Vita's Bluetooth stack (`SceBt`) is built to be the opposite: an RFCOMM/audio
**server** that headsets connect *into*. On 3.65:

- `ksceBtSendSpp` to a freshly-paired iPhone returns `0x802F0703` — "no RFCOMM channel to this
  device." Pairing/ACL is not a data channel.
- There is **no exported function that opens an outbound RFCOMM channel**. The CONNECTION_REQUEST
  sender (`sub_02106422`) exists in the module but has **zero callers** — SceBt never initiates an
  L2CAP connection; it only responds. The outbound client profiles (OPP, HFP) are stubbed
  (`0x802F1008` / `0x802F1301`).
- The only exported L2CAP operation is an echo test. A2DP "connect" is really just setting a
  per-service bitmask and letting an internal state machine open the channel — with the PSM coming
  from an internal table, no way to pass your own.

So the clean conclusion was: the Vita can't be an RFCOMM client, therefore it can't do the CarPlay
bootstrap, therefore you need a bridge (a Mac/Linux PC or an ESP32) to do the Bluetooth part. That
is what the original design used.

## 2. The breakthrough: hand-drive SceBt's L2CAP from a kernel plugin

The orphaned CONNECTION_REQUEST sender was the crack in the wall. The *machinery* to open an L2CAP
channel is all present and functional — it's just never driven. From a taiHEN **kernel plugin** we
can drive it ourselves. The spikes that proved each step are in `l2capprobe/`; the finished code is
in `vitaplay/btplugin/` (the `vitaplaybt` kernel module).

All addresses below are **segment-relative** and come from reverse-engineering `SceBt` on firmware
**3.65**. Kernel ASLR moves the module base every boot, but in-segment offsets are stable; resolve
them at runtime from the segment bases (`taiGetModuleInfoForKernel` / `ksceKernelGetModuleInfo`).
`seg0` is `.text` (loaded at VA `0x02100000` in the static dumps); `seg1` is data. For other
firmware, re-derive the handful of functions named here.

### 2a. Seeing incoming L2CAP (RX interception)

The make-or-break question was whether a plugin can observe SceBt's incoming L2CAP traffic. It can.
SceBt's RX loop (`sub_0211BA30`) demuxes PDUs (`sub_0211BFE0`) and routes **L2CAP signaling** to
`sub_02106558(conn, pdu, len)` at **`seg0 + 0x6558`**. Hooking it with
`taiHookFunctionOffsetForKernel(..., segidx=0, 0x6558, thumb=1, ...)` captures every incoming
signaling PDU (CONNECTION_RSP, CONFIG_REQ/RSP, ECHO, …) and, on the connection's data CID, the
RFCOMM bytes. The hook runs in SceBt's RX thread, so it only snapshots each PDU into a ring buffer
and a worker thread does the logging.

The captured buffer is a raw HCI-ACL frame: `[handle:2][acl_len:2][l2cap_len:2][cid:2][payload]`;
the L2CAP signaling code is at `payload[0]`.

### 2b. Sending L2CAP (TX)

Everything SceBt transmits funnels through one engine:
**`sub_021109EC(conn, cid, template, …)`** at `seg0 + 0x109EC`. The `template` is a tiny format
string for the L2CAP *payload* (`'1'/'2'/'4'` = N-byte little-endian scalar, `' '` = separator,
`'#'` = a `(pointer, length)` blob from the varargs). The engine frames the basic L2CAP header from
the CID and length itself. So:

- **Signaling** uses per-code wrappers that call it: CONNECTION_REQUEST `sub_02106422` (code 2),
  CONNECTION_RSP `sub_02106348/02106500` (3), CONFIG_REQ `sub_02106384` (4), DISC `sub_0210646E`
  (6), ECHO `sub_021064B8` (8), INFO `sub_02106E64` (0xb).
- **Raw data** on an open channel: call `sub_021109EC(conn, dcid, "#", buf, len)` directly — it
  emits `[l2cap_len][cid=dcid][buf…]`. This is how we send RFCOMM frames.

We validated TX + RX end-to-end against the live iPhone by sending an ECHO with a `"VITAPLAY"`
payload and catching the echo reply in the RX hook. Injecting L2CAP did not destabilize the stack.

### 2c. Opening a channel the stack will adopt (the key trick)

Sending a CONNECTION_REQUEST works and the iPhone replies CONNECTION_RSP — but SceBt ignores the
response, because its success handler looks the channel up in its own table (`sub_02111544(conn, 5,
scid)`, a *lookup*) and SceBt never created one (it never dials out). So the channel has to be
**pre-created so SceBt adopts it and runs config itself**:

1. Get the per-device connection object: `conn = sub_02111420(state_block, 1, mac0, mac1)` where
   `state_block = seg1 + 0x10` and type 1 = "device slot by MAC." (`sub_02111420` at `seg0+0x11420`.)
2. Create a channel slot: `ch = sub_02111544(conn, 0x14, our_scid)` (`seg0+0x11544`). Key `0x14`
   takes the create path (match field `+0x34`).
3. **Patch the live object** so the lookup handlers find it: set `*(u16*)(ch+0x36) = our_scid` (the
   key the CONN_RSP / CONFIG handlers match on), and clear `*(u32*)(ch+8) = 0` (create leaves a
   non-zero value there that the CONFIG_REQ sender would read as options → garbage/crash).
4. Send our CONNECTION_REQUEST (`sub_02106422(conn, ch)`, with `ch[0x34]=PSM`, `ch[0x36]=scid`).

SceBt then treats the incoming CONNECTION_RSP as its own, stores the remote DCID, **auto-sends
CONFIG_REQ, negotiates MTU (2582), answers the iPhone's CONFIG_REQ, and opens the channel** — all
by itself. Patching a live SceBt channel object did not crash. This "create key-4 + patch the
type-5 key + clear the options word" is the technique the whole thing rests on.

Channel struct fields we rely on: `+0 = conn`, `+4 = flags`, `+8 = config/opts`,
`+0x34 = PSM / inbound key`, `+0x36 = lookup key (scid)`, `+0x38 = remote DCID`, `+0x3a = id`.

### 2d. RFCOMM, by hand

With an open L2CAP channel to the iPhone's RFCOMM PSM (`0x0003`), we speak RFCOMM (TS 07.10)
ourselves over raw L2CAP data sends:

- SABM on DLCI 0 to start the multiplexer → the iPhone replies UA. (SABM(0) = `03 3F 01 1C`.)
- The FCS is CRC-8, reversed polynomial `0xE0`, init `0xFF`, final XOR `0xFF`.
- We are the RFCOMM *initiator*, so for server channel `n`, `DLCI = (n << 1) | 0`.

### 2e. Finding the iAP2 channel (SDP client)

Open a second L2CAP channel to SDP (PSM `0x0001`) with the same technique and send a
`ServiceSearchAttributeRequest` for the iAP2 UUID
`00000000-decafade-decadeaf-decacafe`. The iPhone's reply contains the ProtocolDescriptorList with
`RFCOMM, channel 1` — **the iAP2 service is on RFCOMM channel 1** (the SDP services also name
themselves "Wireless iAP v2" / "AAP Client"). So we open the DLC for DLCI 2 (channel 1, initiator),
exchange modem-status (MSC) and credit-based flow control, and we have a bidirectional iAP2 byte
pipe to the iPhone.

### 2f. Exposing the pipe to userspace

The kernel plugin keeps the RFCOMM/credit bookkeeping and exposes the iAP2 DLC bytes through three
syscalls (`VitaPlayBt` library): `vpbt_status`, `vpbt_read`, `vpbt_write`. A userspace app drives
the iAP2 protocol over them. (Load the plugin at **boot** via taiHEN `config.txt`, not from the app
— a userspace app can't import syscalls from a module it loads itself at runtime; the imports bind
before the module exists and the first call traps.)

## 3. The iAP2 / CarPlay layer (userspace)

On top of the byte pipe, the rest is standard iAP2 CarPlay, ported to C (`iap2c/` = the link-layer
state machine; `vitaplay/src/iap2_ident.c` = the CSM message builders; `vitaplay/src/btboot.c` =
the driver):

1. **Link layer** — the iAP2 link (detect marker `FF 55 …`, synchronization `FF 5A …`, framed
   control-session payloads with the big-endian CSM format `40 40 | len | msgId | params`).
2. **Identification** (`0x1D00 → 0x1D01`) — the wireless accessory profile (name, EA protocol,
   Bluetooth + WirelessCarPlay transport components, supported/received message lists).
3. **MFi authentication** (`0xAA00 → 0xAA01` certificate, `0xAA02 → 0xAA03` signed challenge,
   `0xAA05` success) — an offline MFi identity (PKCS#8 P-256 key + certificate), raw ECDSA over the
   32-byte challenge.
4. **Wi-Fi / CarPlay handoff** — reply to `0x5702` with `0x5703` (AccessoryWiFiConfiguration: SSID,
   passphrase, security, channel) and to `0x4300` CarPlayAvailability with `0x4301` CarPlayStartSession
   (the receiver's SSID, IP, AirPlay port, device id, public key, source version). This points the
   phone at the Vita's own AirPlay receiver.

The phone then connects over Wi-Fi and runs **a second, independent iAP2 session tunneled inside the
AirPlay data stream** (stream type 130). It repeats the *entire* handshake — identification, MFi,
handoff — and then expects the accessory to subscribe to updates (now-playing `0x5000`, route
guidance `0x5200`, power `0xAE00`, communications `0x4157`, call state `0x4154`). Once subscribed,
the phone streams live now-playing metadata and the CarPlay session is fully established on-device.
(`vitaplay/src/session.c` runs this tunnel through the same `iap2c` engine and sends replies back to
the phone as `iAPSendMessage` events on the AirPlay event channel.)

## 4. Firmware 3.65 quick reference

| Thing | Where |
|---|---|
| L2CAP incoming-signaling handler (hook target) | `seg0 + 0x6558` |
| Universal L2CAP frame sender | `seg0 + 0x109EC` |
| CONNECTION_REQUEST sender (code 2) | `seg0 + 0x6422` |
| CONFIG_REQUEST sender (code 4) | `seg0 + 0x6384` |
| Connection/channel lookup+create | `seg0 + 0x11544` |
| Device-connection getter (by MAC) | `seg0 + 0x11420` |
| BT state block | `seg1 + 0x10` |
| "No RFCOMM channel" error | `0x802F0703` |
| iAP2 service UUID (on the iPhone) | `00000000-decafade-decadeaf-decacafe`, RFCOMM channel 1 |
| Pairing: allow unsupported device | patch the device flag word `+0x10000` (bits `0x11000`) |

Pairing an iPhone needs SceBt's "allow unsupported device" patch (the well-known VitaControl trick);
without it SceBt refuses the pairing.

## 5. What works / what doesn't yet

**Works, entirely on the Vita, no bridge:**
pairing → hand-driven L2CAP → RFCOMM → SDP → iAP2 DLC → identification → MFi auth → Wi-Fi/CarPlay
handoff → the phone connects to the Vita's AirPlay receiver → H.264 video to the screen, touch +
buttons + knob as CarPlay HID, Siri, and the full iAP2 control tunnel with live now-playing.

**Not working yet — CarPlay audio output.** The receiver advertises audio support correctly
(`audioFormats` / `audioLatencies` in `/info`, matching a real head unit field-for-field), the phone
accepts it, takes the audio resource, and streams now-playing — but it never opens the AirPlay audio
stream (types 100/101/102), so there is no sound. We ruled out `/info` encoding, iOS capability
caching, the control-tunnel handshake, the update subscriptions, and resource ownership. The decision
not to open the audio stream is made phone-side for a reason not visible from the Vita. Cracking it
most likely needs a **packet capture from a known-working CarPlay head unit** to diff against, or the
original DiPlay receiver's audio path. All of the receive/decode/play plumbing is already in place
(`vitaplay/src/audio.c`: RTP + ChaCha20-Poly1305, PCM and Opus decode, `sceAudioOut` mixing), so when
the trigger is found it should drop in.

## 6. Code map

| Path | What |
|---|---|
| `vitaplay/` | The CarPlay receiver app (video/touch/Siri/now-playing + the on-device bootstrap) |
| `vitaplay/btplugin/` | The `vitaplaybt` kernel plugin: hand-driven L2CAP/RFCOMM + the `VitaPlayBt` pipe syscalls |
| `vitaplay/src/btboot.c` | Userspace driver of the Bluetooth iAP2 bootstrap over the pipe |
| `vitaplay/src/iap2_ident.c` | iAP2 CSM builders (identification, MFi, handoff, subscriptions) |
| `vitaplay/src/session.c` | AirPlay receiver + the on-device post-handoff iAP2 tunnel |
| `vitaplay/src/iap2_link.c` | The iAP2 link-layer state machine (C) |
| `vitabt/` | The Bluetooth bootstrap as a standalone, reusable library |

(The reverse-engineering spike projects and the original Mac/Linux bridge this work replaces are in
the development history, not in this release.)

## 7. Lineage, license, and keys

The protocol stack is ported from **PlayPort**, **DiPlay** and **xcertplay**, which are GPL-3.0;
this work is GPL-3.0 too. The MFi accessory identity (`identity.pk8` + `certificate.p7b`) is **not**
in this repo and must never be committed or shipped — supply your own in
`ux0:data/VitaPlay/offline-mfi/`.

## 8. Router-free: making the Vita its own Wi-Fi access point (uAP)

Everything above still needs the Vita and the iPhone on the **same Wi-Fi router**. This section is a
separate investigation into removing the router entirely — the Vita becomes the access point, the
iPhone joins *it*, and CarPlay runs over that link. The receive half is proven end-to-end; the
transmit (downlink) half is the one open item. The reusable bring-up lives in
[`vitauap/`](vitauap/README.md); the research spikes behind it live in the development repo, not this
curated release.

**The chip can do it.** Wi-Fi is a Marvell Avastar **88W8797** behind the `SceWlanBt` kernel module
(internal codename "Robin"; the on-chip firmware is `os0:kd/wlanbt_robin_img_ax.skprx`). `SceWlanBt`
is a **station-only host driver**, but it speaks the standard Marvell / mwifiex host-command protocol
(16-bit command; response = command | 0x8000), and the AP (uAP) commands are part of that protocol.
The command path:

```
sub_02954(adapter, size)             -> cmd node; node[8] = payload ptr (cmdbuf+0xc)
sub_02db4(adapter, node, opcode, len) -> fills the SDIO/mwifiex header + queues it
sub_01cd4(adapter, msg, len, ...)     -> response/event handler; type@msg+2, code@msg+4, result@msg+0xa
```

**The key trick — `bss_type`.** Marvell routes a command to the station or the uAP engine by the
`bss_type` nibble in the `seq_num` field (`seq_num = seq | bss_num<<8 | bss_type<<12`). The station
driver's enqueue (`sub_02db4`) force-zeroes that byte (`cmdbuf[9] = 0`), so a uAP command lands on the
STA engine and the firmware rejects it (`result=1`). Re-stamping `cmdbuf[9] = 0x10`
(`bss_num=0, bss_type=1=UAP`) right after enqueue, before the send-worker DMAs the buffer, makes the
firmware's AP engine accept it. With that one byte fixed:

```
UAP_SYS_CONFIG (0x00b0, SET) + TLVs {SSID, BCAST_SSID, CHANNELBANDLIST, ENCRY_PROTOCOL=open}  -> result=0
UAP_BSS_START  (0x00b1)                                                                        -> result=0
```

…and the SSID beacons. An iPhone sees it, **associates, and stays connected** — the firmware handles
auth/association autonomously and raises the standard Marvell uAP events through `sub_01cd4`
(`0x002d UAP_STA_ASSOC`, `0x002c/0x0043/0x0044` BSS start/active/idle). Command IDs:
`UAP_SYS_CONFIG 0x00b0`, `UAP_BSS_START 0x00b1`, `UAP_BSS_STOP 0x00b2`; uAP TLVs (prop. base 0x100):
SSID `0x0000`, MAC_ADDRESS `0x12b`, CHANNELBANDLIST `0x12a`, BCAST_SSID `0x130`, ENCRY_PROTOCOL
`0x140`. The authoritative wire reference is mainline Linux `mwifiex` (`uap_cmd.c` / `fw.h`).

**The OS can't launch an app while the AP is up.** Driving the firmware into AP mode behind the OS's
back is incompatible with the app-launch transition on 3.65 — launching *any* app (VitaShell too)
while the AP is beaconing **kernel-panics**, with zero plugin hooks active and no client connected, so
it's the OS, not us. The idle shell tolerates the AP for minutes; only the launch (and exit)
transition trips it. **The ordering flip solves it:** launch the app *first* (no AP yet → normal
startup), then raise the AP *underneath* the already-running process. So the real architecture is
*app runs → app raises AP → app serves the phone*, never *AP up → launch app*.

**The receive half works.** With the AP up under a running app, the app (an **unsafe self**, needed
to bind privileged ports and import `SceNetPs`) configures the Wi-Fi interface directly, bypassing the
station connection manager (`sceNetCtlInit`'s connect path, which also panics in AP mode):

```
sceNetSyscallGetIfList         -> interfaces: lo0, bt0, wlan0, phone0 (entry stride 0x140)
sceNetSyscallIoctl(wlan0, SIOCSIFADDR  192.168.5.1)   rc=0   (FreeBSD ioctl ABI matches the Vita stack)
sceNetSyscallIoctl(wlan0, SIOCSIFNETMASK 255.255.255.0) rc=0
sceNetSyscallIoctl(wlan0, SIOCSIFFLAGS  UP)           rc=0   -> flags 0x8843
```

(The ioctl socket must come from `sceNetSyscallSocket`, not libc `socket()` — different descriptor
spaces.) With `wlan0` addressed and up, a plain userland UDP socket bound to `:67` **receives the
iPhone's DHCP DISCOVER**, and a minimal DHCP server answers with an OFFER/ACK. So uplink
(phone → Vita) and the whole IP-stack integration are proven.

**The open item — downlink (Vita → phone).** The DHCP OFFER is received, built and `sendto()`-s
successfully, but the phone never sees it. The strong hypothesis, by direct analogy to the
command-path `bss_type` fix, is that the host's **data TX** path tags outgoing `wlan0` frames with the
*station* `bss_type` in the per-packet TxPD, so the firmware won't place them on the uAP BSS. Uplink
works because the firmware delivers received frames regardless; downlink needs the TxPD `bss_type` set
to uAP. The next step is to find the per-frame transmit function, read its TxPD, and stamp
`bss_type=uAP` — the mirror of the `cmdbuf[9]=0x10` command fix.

**Status:** router-free is **proven viable** — AP up under a live app, interface self-configured, phone
associated, uplink + DHCP working — with **downlink delivery the one unsolved piece.** The
router-based path in sections 2–6 is the working, shipping configuration.
