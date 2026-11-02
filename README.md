# VitaPlay — wireless CarPlay on the PS Vita, with no bridge

An experimental project that turns a hacked **PS Vita** into a **wireless CarPlay receiver** —
including the Bluetooth bring-up that normally requires a second device. An iPhone pairs to the
Vita, the **Vita itself** runs the Bluetooth iAP2 bootstrap and the Wi-Fi handoff, and the phone
then streams CarPlay to the Vita over Wi-Fi.

The hard part — and the reason this didn't exist before — is that wireless CarPlay needs the
accessory to be a Bluetooth **RFCOMM client** to the iPhone, which the Vita's `SceBt` stack won't
do on its own. We got it to do it anyway, from a kernel plugin, with **no bridge PC or ESP32**.

> **Status: beta.** The whole chain runs on the Vita — pairing, the Bluetooth iAP2 bootstrap, the
> Wi-Fi/CarPlay handoff, H.264 video to the screen, touch + buttons + knob as CarPlay HID, Siri, and
> the iAP2 control session with live now-playing. **The one piece not working yet is audio output**
> (the phone won't open the audio stream; see the findings). Everything else works.
>
> **Research bonus — router-free (no shared Wi-Fi):** the Vita can also be driven into being its own
> **Wi-Fi access point** so the iPhone joins it directly, with no router. This is *proven viable* —
> the AP comes up under the running app, the phone associates, and the Vita's DHCP server hands it an
> address — but one piece (downlink delivery to the phone) is still unsolved, so it's not a usable
> mode yet. See [`FINDINGS.md` §8](FINDINGS.md) and [`vitauap/`](vitauap/README.md). The shipping
> configuration remains a shared Wi-Fi network.
>
> Experimental, GPL-3.0, as-is — no warranty or support promise. Not affiliated with or endorsed by
> Apple or Sony. CarPlay and iAP2 are trademarks/technologies of Apple Inc.

## Three things in this repo

- **The app** — [`vitaplay/`](vitaplay/README.md): the CarPlay receiver you install on the Vita.
  Builds `VitaPlay.vpk`. Set up Wi-Fi right on the home screen (no file editing). See its README to
  build, install (including the required kernel-plugin boot-load step) and use.

- **The findings** — [`FINDINGS.md`](FINDINGS.md): the write-up of *how* this works — why it looked
  impossible, the breakthrough of hand-driving `SceBt`'s L2CAP from a kernel plugin (the RX hook,
  the TX engine, and the trick that makes SceBt adopt and configure a channel it never dialed),
  then RFCOMM / SDP / iAP2 / MFi / the handoff, a firmware-3.65 offset reference, and an honest
  account of what works vs. the open audio item. Start here if you want to understand or port it.

- **The library** — [`vitabt/`](vitabt/README.md): the Bluetooth bootstrap carved out as a clean,
  reusable, separately-buildable library so other Vita homebrew can make the Vita an RFCOMM client
  to an iPhone's iAP2 service. It gives you a live iAP2 **byte pipe** on-device and a documented
  three-call API; the iAP2 protocol on top is yours to drive (or reuse the included link layer).

- **The router-free library (research)** — [`vitauap/`](vitauap/README.md): a sibling toolkit for the
  *other* radio — driving the Vita's Wi-Fi into **access-point (uAP) mode** so a phone can join the
  Vita with no router. Proven to the point where the phone associates and the Vita serves DHCP;
  downlink to the phone is still unsolved (see [`FINDINGS.md` §8](FINDINGS.md)). Shared as a head
  start for anyone who wants to finish router-free CarPlay.

The spirit of the release: **here's what we found, and here's a way to use it — it's yours to do
with what you want.**

## How it works, in one picture

```
  iPhone  --Bluetooth-->  Vita (vitaplaybt kernel plugin: hand-driven L2CAP -> RFCOMM -> iAP2)
                              |  identification + MFi auth + Wi-Fi/CarPlay handoff
                              v
  iPhone  --Wi-Fi------->  Vita (AirPlay receiver: video, touch/knob HID, Siri, now-playing)
```

Both the Bluetooth bootstrap and the post-handoff iAP2 control tunnel run entirely on the Vita.

## Repo layout

| Path | What |
|---|---|
| [`vitaplay/`](vitaplay/) | The CarPlay receiver app (video/touch/Siri/now-playing + the on-device bootstrap) |
| [`vitabt/`](vitabt/) | Reusable dev/homebrew library: the kernel plugin + the iAP2 byte-pipe API + link layer |
| [`vitauap/`](vitauap/) | Router-free library (research): drive `SceWlanBt` into Wi-Fi AP (uAP) mode — see §8 |
| [`FINDINGS.md`](FINDINGS.md) | How the on-device Bluetooth bootstrap (and the router-free uAP work, §8) were reverse-engineered |
| `VitaPlay-beta.vpk` | Prebuilt app to install with VitaShell (the `vitaplaybt` kernel plugin is bundled inside it) |
| `vitaplaybt.skprx` | The kernel plugin as a **standalone file** — already inside the VPK; provided separately for convenience |
| `LICENSE` | GPL-3.0 |

(The iAP2 link layer is vendored inside both `vitaplay/` and `vitabt/`, so each builds on its own.
The reverse-engineering spike projects and the original Mac/Linux bridge this work replaces live in
the development history, not in this release.)

## Quick start

1. Build and install the app — see [`vitaplay/README.md`](vitaplay/README.md). You'll need VitaSDK,
   an iOS MFi accessory identity (not shipped — supply your own), and the `vitaplaybt` kernel plugin
   boot-loaded via taiHEN.
2. Set the Wi-Fi network and password on VitaPlay's home screen, pair your iPhone, and connect.
3. To build something of your own on the Bluetooth capability, start from
   [`vitabt/README.md`](vitabt/README.md).

## Requirements

A Vita on firmware the plugin supports (reverse-engineered for **3.65**; other firmware needs the
`SceBt` offsets re-derived — see FINDINGS.md), HENkaku/Ensō with Unsafe Homebrew, an iPhone, a Wi-Fi
network both devices join, and your own MFi accessory identity.

## Lineage and license

The CarPlay/AirPlay protocol stack is ported from **PlayPort**, **DiPlay** and **xcertplay**, which
are GPL-3.0; this project is **GPL-3.0** as well (see [`vitaplay/LICENSE`](vitaplay/LICENSE)). The
MFi accessory identity (private key + certificate) is **not** in this repo and must never be
committed or redistributed.
