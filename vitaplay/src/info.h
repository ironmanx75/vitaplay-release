/* The /info plist the phone reads before requesting streams (port of AirPlayInfoPlist.kt). */
#pragma once

#include "bplist.h"

#define MAIN_DISPLAY_UUID "b7e6c5a0-1111-4000-8000-000000000001"

pl_node *info_build(const vp_config *config);
