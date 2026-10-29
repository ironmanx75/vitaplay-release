/*
 * CarPlay timing port (simplified port of NtpClock.kt): answers the phone's PT_REQUEST (210)
 * packets and sends our own requests once a second. Clock steering is not ported yet; it only
 * matters for audio, which VitaPlay does not play yet.
 */
#pragma once

#include "common.h"

typedef struct ntp_clock ntp_clock;

/* peer_ip is in network byte order; peer_port 0 disables outgoing requests. */
ntp_clock *ntp_start(uint32_t peer_ip, int peer_port);
void ntp_stop(ntp_clock *clock);
