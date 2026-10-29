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

1. Enable **Unsafe Homebrew** (HENkaku settings) — VitaPlay loads a kernel plugin.
2. Install `VitaPlay.vpk` with VitaShell on a hacked Vita (HENkaku/Ensō).
3. **Boot-load the Bluetooth plugin.** The `vitaplaybt` kernel plugin ships inside the VPK and must
   be resident before VitaPlay starts (a userspace app can't load a kernel module it then calls).
   Add it to `ux0:tai/config.txt` under `*KERNEL`, then reboot:
   ```
   *KERNEL
   ux0:app/VPLY00001/vitaplaybt.skprx
   ```
4. Copy the accessory identity into `ux0:data/VitaPlay/offline-mfi/`:
   `identity.pk8` (PKCS#8 P-256 key) and `certificate.p7b`. VitaPlay does not ship these. PlayPort's
   README describes where the public copies come from (DiPlay's release APK under
   `assets/offline-mfi/`). Do not redistribute them.
5. Connect the Vita to the same Wi-Fi network as the iPhone and start VitaPlay. On the home screen,
   set the Wi-Fi network (**Square**) and password (**Triangle**) — see "Wi-Fi setup" above. The
   status screen shows the IP, device ID, whether the identity loaded, and the Wi-Fi settings.
6. On the iPhone, pair the Vita over Bluetooth, then connect. The Vita runs the bootstrap and the
   phone switches to CarPlay over Wi-Fi.

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
