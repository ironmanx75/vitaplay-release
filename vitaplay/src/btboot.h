/*
 * On-device Bluetooth iAP2 bootstrap for wireless CarPlay.
 *
 * Replaces the external playport-bridge: a kernel plugin (loaded at boot, see README) opens the
 * RFCOMM iAP2 channel to the iPhone and exposes its bytes through the VitaPlayBt pipe syscalls;
 * this module drives the iAP2 control sequence over that pipe (identification, MFi authentication,
 * and the Wi-Fi/CarPlay handoff), pointing the phone at this Vita's own AirPlay receiver.
 */
#pragma once

/* Starts the bootstrap in a background thread. Safe to call when the kernel plugin is not resident:
 * the pipe reports "down" and the thread simply waits for a connection. */
void btboot_start(void);
