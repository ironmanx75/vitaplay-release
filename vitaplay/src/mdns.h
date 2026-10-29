/*
 * Minimal mDNS responder advertising "<name>._airplay._tcp.local" with the CarPlay TXT records
 * from CarPlayBonjourProtocol.kt. Replaces JmDNS / dns-sd, which the Vita does not have.
 */
#pragma once

#include "common.h"

int mdns_start(void);
