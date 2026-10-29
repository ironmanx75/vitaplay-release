/* iAP2 CSM builders for the wireless CarPlay bootstrap: IdentificationInformation (0x1D01), the
 * MFi auth messages, and the Wi-Fi/CarPlay handoff replies (0x5703 / 0x4301). See iap2_ident.c. */
#pragma once

/* Build the IdentificationInformation CSM frame (starting 0x4040) into out[0..cap).
 * mac6 = the accessory's (Vita's) Bluetooth MAC; ssid = the Wi-Fi network for wireless CarPlay.
 * Returns the frame length, or -1 if it did not fit. */
int iap2_build_identification(unsigned char *out, int cap, const unsigned char mac6[6],
                              const char *name, const char *model, const char *manufacturer,
                              const char *serial, const char *fw, const char *hw,
                              const char *ea_protocol, const char *language, const char *ssid);

/* Build a CSM message carrying a single parameter 0 = p0[0..n): frame 0x4040|len|msgid|{len|0|p0}.
 * Returns the frame length, or -1 if it did not fit. Used for AuthenticationCertificate (0xAA01)
 * and AuthenticationResponse (0xAA03). */
int iap2_build_bytes_msg(unsigned char *out, int cap, unsigned msgid,
                         const unsigned char *p0, int n);

/* Point *out at parameter 0's payload inside a CSM frame; returns its length, or -1. */
int iap2_get_param0(const unsigned char *frame, int flen, const unsigned char **out);

/* Build AccessoryWiFiConfigurationInformation (0x5703): the Wi-Fi the phone should join for
 * wireless CarPlay. Params: (0=BSSID omitted) 1=ssid, 2=passphrase, 3=u8 security, 4=u8 channel.
 * Returns the frame length, or -1 if it did not fit. */
int iap2_build_wifi_config(unsigned char *out, int cap, const char *ssid, const char *passphrase,
                           int security, int channel);

/* Build CarPlayStartSession (0x4301): points the phone at this receiver over Wi-Fi.
 * group 1 wireless { 0=ssid, 1=passphrase, 2=u8 channel, 3=ip, 4=u8 security }; u32 2=airPlayPort;
 * str 3=deviceId; str 4=publicKey; str 5=sourceVersion. Returns the frame length, or -1. */
int iap2_build_carplay_start(unsigned char *out, int cap, const char *ssid, const char *passphrase,
                             int security, int channel, const char *ip, int airplay_port,
                             const char *device_id, const char *public_key,
                             const char *source_version);

/* Build one of the CarPlay control-session subscription messages the accessory sends after auth
 * (StartNowPlayingUpdates, StartRouteGuidanceUpdates, StartPowerUpdates, StartCommunicationsUpdates,
 * StartCallStateUpdates). index 0..4; returns the frame length, or -1 when the index is out of
 * range or it did not fit. */
int iap2_build_subscription(unsigned char *out, int cap, int index);
