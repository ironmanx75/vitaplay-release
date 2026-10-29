/* Host stand-in for the Vita header, for protocol tests on macOS/Linux. */
#pragma once
#include <stdint.h>
uint64_t sceKernelGetProcessTimeWide(void);
