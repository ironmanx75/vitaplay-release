/* Host stand-in for the Vita header, for protocol tests on macOS/Linux. */
#pragma once
#include <stddef.h>
int sceKernelGetRandomNumber(void *output, size_t size);
