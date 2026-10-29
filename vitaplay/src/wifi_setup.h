/*
 * On-screen Wi-Fi setup: lets the user type the network name and password with the Vita's
 * on-screen keyboard and saves them to config.txt, so no manual file editing is needed.
 */
#pragma once

#include <stdbool.h>

/* Opens the on-screen keyboard to edit a value. Writes the confirmed text (UTF-8) into out and
 * returns true; returns false (leaving out unchanged) if the user cancelled. password hides input. */
bool wifi_prompt(const char *title, const char *initial, char *out, int out_cap, bool password);

/* Writes g_config.wifi_ssid / wifi_pass into APP_DIR/config.txt, preserving the other lines. */
void wifi_save_config(void);
