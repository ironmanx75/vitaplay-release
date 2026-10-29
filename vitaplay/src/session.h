/*
 * CarPlay AirPlay control session (port of AirPlaySession.kt): RTSP routing, pairing, auth,
 * /info, stream SETUP/TEARDOWN, the encrypted event channel used for HID input, and timing.
 */
#pragma once

#include "common.h"
#include "hid.h"

typedef enum {
    SESSION_IDLE,      /* no phone connected */
    SESSION_CONNECTED, /* control connection open, not yet verified */
    SESSION_VERIFIED,  /* pair-verify done, control channel encrypted */
    SESSION_STREAMING, /* screen stream set up */
} session_state;

/* Starts the AirPlay listener on AIRPLAY_PORT. */
int session_server_start(void);

session_state session_current_state(void);
void session_peer_name(char *out, size_t max);

/* Input from the Vita; no-ops until the event channel is up. */
void session_send_touch(const touch_contact contacts[TOUCH_CONTACTS]);
void session_send_knob(const knob_state *state);
void session_request_keyframe(void);

/* Media and telephony keys: a press and its release (indices into the HID descriptors). */
#define MEDIA_PLAY_PAUSE 3
#define MEDIA_NEXT 4
#define MEDIA_PREVIOUS 5
#define TELEPHONY_HOOK_SWITCH 1 /* answers a ringing call, hangs up an active one */
void session_send_media(int index);
void session_send_telephony(int index);
void session_request_siri(void);

/* Day/night appearance; remembered and resent whenever the event channel (re)connects. */
void session_set_night_mode(bool night);
/* True while the phone reports a phone call (modesChanged app state 2 owned by the phone). */
bool session_call_active(void);
