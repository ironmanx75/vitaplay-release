/* CarPlay HID descriptors and report encoders (port of AirPlayHid.kt). */
#pragma once

#include "bplist.h"
#include "common.h"

#define TOUCH_HID_UID 0x2a2a2a2a
#define KNOB_HID_UID 0x2a2a2a2b
#define MEDIA_HID_UID 0x2a2a2a2c
#define TELEPHONY_HID_UID 0x2a2a2a2d
#define TOUCH_CONTACTS 2

typedef struct {
    bool down;
    int x; /* display pixels */
    int y;
} touch_contact;

typedef struct {
    bool select, home, back;
    int x, y, wheel;
} knob_state;

pl_node *hid_touch_device(int x_max, int y_max, const char *display_uuid);
pl_node *hid_knob_device(const char *display_uuid);
pl_node *hid_media_device(const char *display_uuid);
pl_node *hid_telephony_device(const char *display_uuid);

void hid_touch_report(uint8_t out[TOUCH_CONTACTS * 6], const touch_contact contacts[TOUCH_CONTACTS]);
void hid_knob_report(uint8_t out[4], const knob_state *state);
