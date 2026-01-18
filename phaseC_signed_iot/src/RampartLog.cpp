#include "RampartLog.h"
#include <stdarg.h>
#include <time.h>

namespace RampartLog {

bool wallClockIsSynced() {
  return time(nullptr) >= 1700000000;
}

static void formatWallUtc(char* out, size_t outLen) {
  if (!out || outLen == 0) return;

  if (!wallClockIsSynced()) {
    snprintf(out, outLen, "UNSYNC");
    return;
  }

  time_t now = time(nullptr);
  struct tm tm_utc;
  gmtime_r(&now, &tm_utc);

  snprintf(out, outLen, "%04d-%02d-%02dT%02d:%02d:%02dZ",
           tm_utc.tm_year + 1900, tm_utc.tm_mon + 1, tm_utc.tm_mday,
           tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec);
}

void logf(const char* tag, const char* fmt, ...) {
  char wall[32];
  formatWallUtc(wall, sizeof(wall));

  Serial0.printf("[up=%lums wall=%s][%s] ",
                 (unsigned long)millis(),
                 wall,
                 tag ? tag : "LOG");

  char msg[256];
  va_list args;
  va_start(args, fmt);
  vsnprintf(msg, sizeof(msg), fmt ? fmt : "", args);
  va_end(args);

  Serial0.print(msg);
  Serial0.print("\n");
}

} // namespace RampartLog
