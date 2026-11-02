# VitaPlay

An experimental wireless CarPlay receiver for the PS Vita, written in C with VitaSDK. It is a
port of the protocol stack in [PlayPort](https://github.com/youcci/playport), which itself is
ported from [DiPlay](https://github.com/shihabal3amri/DiPlay) and
[xcertplay](https://github.com/shilapi/xcertplay).

> Not affiliated with or endorsed by Apple, Sony, or the authors of those projects. CarPlay is a
> trademark of Apple Inc. This is not a certified product.

## Status

| Piece | State |
|---|---|
| mDNS advertising (`_airplay._tcp`) | Done; verified with macOS `dns-sd` |
| Pair-setup (SRP-6a, PIN 3939) and pair-verify | Done; verified against an independent client |
| Encrypted control channel, `/info`, SETUP, TEARDOWN | Done; verified |
| MFi `/auth-setup` with a software identity | Done; signature verified |
| Timing port | Answers requests; clock steering not ported (only needed for audio) |
| Screen stream: decrypt, avcC → SPS/PPS, Annex B | Done |
| H.264 decode → screen | **Done; runs on hardware** — CarPlay video verified against a real iPhone |
| Touch and buttons → CarPlay HID over the event channel | Done |
| Bluetooth iAP2 bootstrap | **On the Vita** via the `vitaplaybt` kernel plugin: RFCOMM, identification, MFi auth and the Wi-Fi/CarPlay handoff all run on-device. No bridge |
| iAP2 over the AirPlay tunnel (after the Wi-Fi handoff) | **On the Vita** — the post-handoff control session runs through the same `iap2c` engine; Siri and live now-playing work. No bridge |
| Audio output (PCM/Opus/AAC) | Receive/decrypt/decode/play plumbing done (`src/audio.c`); **the phone does not yet open an audio stream, so there is no sound** — see "Known limitation" |
| Wired CarPlay | Out of scope for the handheld (no USB host mode) |

This is the beta: the whole wireless CarPlay bring-up runs on the Vita with no bridge PC — pairing,
the Bluetooth iAP2 bootstrap, the Wi-Fi handoff, video, touch/buttons/knob, Siri and the control
session with now-playing. See [`../FINDINGS.md`](../FINDINGS.md) for how it works. The host tests in
`tests/host/run.sh` (driven by `tools/FakePhone.java`) still exercise the crypto/network paths.

### Known limitation: no audio output yet

The receiver advertises audio correctly and the phone accepts it, takes the audio resource and
streams now-playing metadata — but it never opens the AirPlay audio stream, so there is no sound.
The cause is on the phone side and isn't visible from the Vita; the entire receive/decode/play path
is already implemented, so this is expected to drop in once the trigger is found (likely needs a
packet capture from a known-working head unit to diff). Everything else works.

## How a phone reaches the Vita

Wireless CarPlay always begins over Bluetooth. The phone exchanges iAP2 messages over RFCOMM and
receives the Wi-Fi details and the receiver's address. Only then does it connect to the AirPlay
service.

VitaPlay now does this first step **on the Vita itself**. The `vitaplaybt` kernel plugin (packed
into the VPK) opens the RFCOMM iAP2 channel to the iPhone and exposes its bytes to userspace;
`src/btboot.c` drives the iAP2 control sequence over it — identification, MFi authentication, then
the Wi-Fi/CarPlay handoff (`0x5703` AccessoryWiFiConfiguration and `0x4301` CarPlayStartSession),
pointing the phone at this Vita's own AirPlay address, port, device ID and public key. No bridge
PC is involved in the bootstrap.

The kernel plugin must be resident **before** VitaPlay starts (a userspace app cannot load a kernel
module it then calls, because syscall imports are bound at app-load time). So it is loaded at boot
through taiHEN. After installing the VPK, add the plugin to `ux0:tai/config.txt` under `*KERNEL`
and reboot:

```
*KERNEL
ux0:app/VPLY00001/vitaplaybt.skprx
```

After the Wi-Fi handoff the phone runs iAP2 again through the AirPlay data stream (type 130). That
second iAP2 session now also runs **on the Vita** (`src/session.c` drives it through the same
`iap2c` engine and replies via `iAPSendMessage` events), so Siri and now-playing work with no bridge.

### Wi-Fi setup (on-screen, no file editing)

Wireless CarPlay needs the Vita and the iPhone on the same Wi-Fi network, and the Vita has to tell
the phone that network's name and password during the handoff. Set them right on VitaPlay's home
screen — no `config.txt` editing:

- **Square** → enter the Wi-Fi network name (SSID). Defaults to the network the Vita is on.
- **Triangle** → enter the Wi-Fi password.

Both are saved automatically; the status screen shows the SSID and whether a password is set. (They
are stored in `config.txt` as `wifi_ssid=` / `wifi_pass=` if you prefer to edit them by hand.)

Advanced `ux0:data/VitaPlay/config.txt` keys:

```
wifi_pass=<the Wi-Fi password>   # or set it on-screen with Triangle
wifi_ssid=<network name>         # optional: defaults to the network the Vita is on
wifi_security=2                  # 0 none, 1 WEP, 2 WPA/WPA2 (default), 3 WPA3-transition, 4 WPA3
wifi_channel=0                   # optional; 0 lets the phone scan
```

(`iap_relay=` from the bridge era is obsolete — the iAP2 tunnel now runs on the Vita — and is
ignored.)

## Build

```sh
# VitaSDK in ~/vitasdk, plus: vdpm install mbedtls libsodium opus libvita2d
make            # -> VitaPlay.vpk
make assets     # regenerate the LiveArea images (needs Java)
```

## Install and set up

### What you need first

- A **PS Vita or PS TV on firmware 3.65**, jailbroken with **HENkaku + Ensō**. The kernel plugin's
  reverse-engineered offsets are for 3.65; other firmware needs them re-derived (see FINDINGS.md).
- **Unsafe Homebrew enabled** — *Settings → HENkaku Settings → Enable unsafe homebrew*. VitaPlay
  loads a kernel plugin, so it will not run without this.
- **VitaShell** on the Vita (to install the VPK and edit `config.txt`).
- A way to copy files to the Vita: USB (VitaShell → `SELECT` for USB), or FTP (VitaShell → `SELECT`,
  then connect to the shown `ftp://<vita-ip>:1337/`).
- An **MFi accessory identity** — not shipped; see step 4.
- An **iPhone** and a **Wi-Fi network both devices join** (this build still needs a shared router;
  router-free is research-only — see the main README).

### Step 1 — Install the app

Copy **`VitaPlay-beta.vpk`** to the Vita, open **VitaShell**, highlight the `.vpk`, press **✕**, and
confirm the install. It installs as **VitaPlay** with title ID **`VPLY00001`**, and a VitaPlay bubble
appears in the LiveArea.

### Step 2 — Boot-load the Bluetooth kernel plugin

The `vitaplaybt` kernel plugin **ships bundled inside the VPK** — installing the app in step 1 already
placed it on the Vita at:

```
ux0:app/VPLY00001/vitaplaybt.skprx
```

(A **standalone copy, `vitaplaybt.skprx`, is also provided in this release** next to the VPK, in case
you want to inspect it, keep it elsewhere, or load it from a different path. You do **not** need it if
you installed the VPK — the bundled copy at the path above is the same file.)

The plugin must be resident **before** VitaPlay launches — a userspace app can't load a kernel module
it then calls, because syscall imports are bound at app-load time — so taiHEN loads it at boot:

1. In VitaShell, open **`ux0:tai/config.txt`** (press **✕** on it, choose *Open decrypted* / edit).
   If `ux0:tai/` or `config.txt` doesn't exist, create it (most Ensō setups already have one).
2. Find the **`*KERNEL`** section (plugins listed under it load into the kernel). Add this line in
   that section — **not** under `*main` (the userspace section):
   ```
   *KERNEL
   ux0:app/VPLY00001/vitaplaybt.skprx
   ```
   If you prefer the standalone file, copy it somewhere (e.g. `ux0:tai/vitaplaybt.skprx`) and point
   the line there instead — either path works, same plugin.
3. **Save and reboot the Vita.** The plugin only takes effect after a full reboot.

To confirm it loaded: launch VitaPlay — its status screen reports when the Bluetooth bootstrap is
ready, and `ux0:data/VitaPlay/log.txt` logs the plugin pipe coming up. (If you use molecularShell,
the taiHEN plugin list also shows `vitaplaybt` under the kernel modules.)

### Step 3 — Provide the MFi accessory identity

Copy your accessory identity into **`ux0:data/VitaPlay/offline-mfi/`**:

- `identity.pk8` — the PKCS#8 P-256 private key
- `certificate.p7b` — the matching certificate

VitaPlay does **not** ship these, and you must not redistribute them. PlayPort's README documents
where the public copies come from (DiPlay's release APK, under `assets/offline-mfi/`). Without a
valid identity the MFi authentication step fails and the phone won't hand off to CarPlay.

### Step 4 — Wi-Fi and first run

1. Join the Vita to the **same Wi-Fi network as the iPhone** (Vita *Settings → Network*, or let
   VitaPlay's on-screen setup below store it).
2. Launch **VitaPlay**. On the home screen set the Wi-Fi **network name** (press **Square**) and
   **password** (press **Triangle**) via the on-screen keyboard — no file editing needed. The status
   panel shows the IP, device ID, whether the identity loaded, and the current Wi-Fi settings.
3. On the **iPhone**, pair the Vita over **Bluetooth** (Settings → Bluetooth → tap the Vita), then
   confirm the CarPlay prompt. The Vita runs the bootstrap on-device and the phone switches to
   CarPlay over Wi-Fi — video appears on the Vita screen.

### Troubleshooting

- **VitaPlay crashes or closes instantly on launch** → Unsafe Homebrew isn't enabled, or the
  `*KERNEL` line is missing / under the wrong section / points at the wrong path, or you didn't
  reboot after editing `config.txt`.
- **Status screen says the identity didn't load** → `identity.pk8` / `certificate.p7b` aren't in
  `ux0:data/VitaPlay/offline-mfi/` (check exact filenames).
- **Stuck on "Waiting for Wi-Fi"** → the Vita isn't connected to a network yet (step 4.1).
- **Phone pairs but never switches to CarPlay** → usually the MFi identity (step 3) or the handoff
  Wi-Fi settings not matching the network the iPhone is on.
- **No audio** → known limitation (see "Known limitation" above); everything else should work.

Controls: touch screen → CarPlay touch. Cross/Circle/Triangle → select/back/home. Right stick →
knob wheel (up/left previous, down/right next; holding repeats), left stick → knob nudges. Square → play/pause, or answer/hang up during a call. D-pad left/right → previous/next
track, up/down → night/day. START (tapped on its own) → Siri. SELECT toggles the status panel.
START+SELECT quits. Logs go to `ux0:data/VitaPlay/log.txt`.

Night mode follows the Vita's clock (night from 19:00 to 07:00) unless `config.txt` sets
`night_mode=day` or `night_mode=night`; D-pad up/down overrides either until VitaPlay restarts.

## Testing without an iPhone

```sh
java tools/FakePhone.java <vita-ip>
```

This runs pairing, auth-setup, `/info` and SETUP against a running Vita, then streams two
synthetic frames. The frames are random bytes, so the decoder will reject them; the point is to
exercise the network and crypto path on real hardware. For the full host test:

```sh
CC="zig cc" DEPS=/path/to/host-deps tests/host/run.sh
```

`DEPS` must contain host builds of mbedTLS 3.6.5 (`libmbed.a`) and libsodium 1.0.22
(`libsodium.a`) next to their unpacked source trees (for the headers).

## Source map

| VitaPlay | Ported from (PlayPort `protocol/`) |
|---|---|
| `src/session.c` | `AirPlaySession.kt`, parts of `CarPlayMediaEngine.kt` |
| `src/pairing.c`, `src/srp.c`, `src/tlv8.c` | `PairSetup.kt`, `PairVerify.kt`, `Srp6a.kt`, `Tlv8Codec.kt` |
| `src/crypto.c`, `src/cipher.c` | `AirPlayCrypto.kt`, `ControlCipher.kt` |
| `src/mfi.c` | `MfiSapAuthSetup.kt`, `LocalMfiAuthenticationClient.kt` |
| `src/info.c`, `src/hid.c` | `AirPlayInfoPlist.kt`, `AirPlayHid.kt` |
| `src/screen.c` | `ScreenStream.kt` |
| `src/ntp.c` | `NtpClock.kt` (simplified) |
| `src/bplist.c`, `src/rtsp.c` | `BplistCodec.kt`, `RtspMessage.kt` |
| `src/mdns.c` | replaces JmDNS/`dns-sd` (`CarPlayBonjourProtocol.kt` TXT records) |
| `src/video.c`, `src/main.c` | new: `sceAvcdec`, vita2d, touch and buttons |

## License

GPL-3.0, the same license as the projects it is ported from. See `LICENSE`.
