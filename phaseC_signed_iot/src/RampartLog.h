#pragma once
#include <Arduino.h>

namespace RampartLog {
  void logf(const char* tag, const char* fmt, ...);
  bool wallClockIsSynced();
}
