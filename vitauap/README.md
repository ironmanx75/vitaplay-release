# vitauap — make the PS Vita its own Wi-Fi access point (uAP)

A reverse-engineered technique (and reference kernel plugin) for driving the Vita's Wi-Fi into
**access-point mode** so an iPhone — or any client — can join the Vita **directly, with no router**.
This is the missing piece for *router-free* wireless CarPlay ([`../vitaplay/`](../vitaplay/)), but the
capability is general: it's a SoftAP on the Vita.

> **Status: research / partial.** The receive half is proven end-to-end — the AP comes up, an iPhone
> associates and stays connected, and a userland DHCP server on the Vita receives the client's
> requests. **Downlink (Vita → client) is not yet working**, so the client can't complete DHCP and
> the link isn't usable for traffic yet. See [`../FINDINGS.md` §8](../FINDINGS.md) for the full story
> and the exact next step. This is a toolkit and a write-up, not a finished feature.
>
> Experimental, GPL-3.0, as-is. Not affiliated with Apple or Sony.

## The idea in three points

- **The chip can do AP mode.** Wi-Fi is a Marvell Avastar **88W8797** behind `SceWlanBt` (codename
  "Robin"). It's a *station-only host driver*, but it speaks the standard Marvell/mwifiex host-command
  protocol, and the on-chip firmware implements the uAP commands. We confirmed the firmware accepts
  `UAP_SYS_CONFIG` (`0x00b0` → `0x80b0`, `result=0`).

- **The one trick that makes it work: `bss_type`.** The station driver's command-enqueue zeroes the
  `seq_num` byte that selects the station-vs-AP engine, so uAP commands get mis-routed and rejected.
  Re-stamp that byte to the uAP value (`cmdbuf[9] = 0x10`) right after enqueue, and the firmware's AP
  engine accepts the command. `UAP_SYS_CONFIG` + `UAP_BSS_START` with that fix → the SSID beacons and
  clients associate. (See [`include/vitauap.h`](include/vitauap.h) for the offsets and sequence.)

- **Ordering matters.** You can't launch an app while the AP is already up — the OS kernel-panics on
  the app-launch transition (true of VitaShell too; it's the OS, not this code). So the app must
  launch **first**, then raise the AP underneath the already-running process (hold the AP down until
  the app signals it's ready). The development repo has a dedicated plugin that does exactly this.

## What's in the box

- [`plugin/softap.c`](plugin/softap.c) — the minimal reference bring-up: resolve `SceWlanBt` at
  runtime, send `UAP_SYS_CONFIG(SET)` + `UAP_BSS_START` with the `bss_type` fix, and log each
  firmware result. This is the clearest demonstration of the technique.
- [`include/vitauap.h`](include/vitauap.h) — the porting reference: FW-3.65 offsets, the uAP command
  and TLV IDs, and the `bss_type` trick documented in one place.
- The research spikes behind this (firmware probe, RX/DHCP capture, the ordering-flip bring-up, the TX-frame dump, the segment dumper) live in the development repo, not this curated release.

## Interface setup (userland side)

Once the AP is up, the app assigns the Wi-Fi interface an address and brings it up **without** the
station connection manager (which panics in AP mode). This needs an **unsafe self** (to bind
privileged ports and import `SceNetPs`):

```
int s = sceNetSyscallSocket("cfg", AF_INET, SOCK_DGRAM, 0);   /* NOT libc socket() */
sceNetSyscallIoctl(s, SIOCSIFADDR,    ifr(wlan0, 192.168.5.1));
sceNetSyscallIoctl(s, SIOCSIFNETMASK, ifr(wlan0, 255.255.255.0));
sceNetSyscallIoctl(s, SIOCSIFFLAGS,   ifr(wlan0, IFF_UP));
```

The FreeBSD ioctl ABI (`SIOCSIFADDR 0x8020690c`, `SIOCSIFNETMASK 0x80206916`, `SIOCSIFFLAGS
0x80206910`; `struct ifreq { char name[16]; sockaddr_in; }`) matches the Vita stack. After that a
plain userland UDP socket on the interface works. The development repo has a complete, working
example of this (interface enumeration, config, and a minimal DHCP server). Note this requires an
**unsafe self**, so it is a research tool — not part of the shipping (safe-self) beta app here.

## Build

```
export VITASDK=/path/to/vitasdk
cd plugin && make        # -> softap.skprx (a taiHEN kernel plugin)
```

Boot-load it via taiHEN `config.txt` under `*KERNEL`. **Caution:** it drives the live Wi-Fi driver;
a bad run can hiccup Wi-Fi — a reboot restores it. Run with Wi-Fi enabled but not connected.

## The open item — downlink

Frames from the Vita to the client aren't being delivered. The strong hypothesis (by analogy to the
command-path fix) is that the host's **data-TX** path tags outgoing frames with the *station*
`bss_type` in the per-packet TxPD, so the firmware won't put them on the uAP BSS. The next step is to
find the per-frame transmit function (not the periodic `sub_02360` worker), read its TxPD, and stamp
`bss_type = uAP` — the mirror of the command fix. Details and candidates are in `../FINDINGS.md` §8.

## License

GPL-3.0, matching the rest of the project. No MFi keys or other secrets are part of this component.
