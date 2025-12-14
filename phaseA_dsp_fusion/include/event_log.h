// Fixed-size append-only event log with ring-buffer semantics.
//
// Hard requirements:
// - Minimal EventRecord + EventType enum
// - Append-only fixed-size ring buffer
// - log_init(), log_append(const EventRecord&), log_dump_serial()

#pragma once

#include <Arduino.h>

enum class EventType : uint8_t {
  BOOT = 0,
  ARMED_CHANGED = 1,
  AUDIO_SUSPECT = 2,
  IMPACT_SUSPECT = 3,
  ALERT_FIRED = 4,
  ALERT_CLEARED = 5,
  TEST = 6,
};

// Minimal record; keep it POD and small.
struct EventRecord {
  uint32_t seq;
  uint32_t t_ms;
  EventType type;
  uint8_t fsm_state;
  uint8_t flags;

  // Snapshot of select features (scaled).
  int16_t audio_rms;
  int16_t audio_peak;
  uint16_t audio_zcr_q15;
  uint16_t audio_hfe;

  int16_t accel_mag_mg;
  int16_t accel_peak_mg;
  uint16_t accel_impulse_mg;
};

// Log capacity: tuned for low RAM use.
#ifndef RAMPART_EVENT_LOG_CAPACITY
#define RAMPART_EVENT_LOG_CAPACITY 128u
#endif

struct EventLog {
  EventRecord buf[RAMPART_EVENT_LOG_CAPACITY];
  uint16_t head;   // next write index
  uint16_t count;  // number of valid records
  uint32_t next_seq;
};

// Global log instance provided by main.cpp.
extern EventLog g_event_log;

inline const char *event_type_str(EventType t) {
  switch (t) {
    case EventType::BOOT:
      return "BOOT";
    case EventType::ARMED_CHANGED:
      return "ARMED_CHANGED";
    case EventType::AUDIO_SUSPECT:
      return "AUDIO_SUSPECT";
    case EventType::IMPACT_SUSPECT:
      return "IMPACT_SUSPECT";
    case EventType::ALERT_FIRED:
      return "ALERT_FIRED";
    case EventType::ALERT_CLEARED:
      return "ALERT_CLEARED";
    case EventType::TEST:
      return "TEST";
    default:
      return "?";
  }
}

inline void log_init(EventLog &log) {
  log.head = 0;
  log.count = 0;
  log.next_seq = 1;
}

inline void log_init() { log_init(g_event_log); }

inline void log_append(EventLog &log, const EventRecord &rec_in) {
  EventRecord rec = rec_in;
  rec.seq = log.next_seq++;
  log.buf[log.head] = rec;
  log.head = (uint16_t)((log.head + 1u) % (uint16_t)RAMPART_EVENT_LOG_CAPACITY);
  if (log.count < (uint16_t)RAMPART_EVENT_LOG_CAPACITY) {
    log.count++;
  }
}

inline void log_append(const EventRecord &rec) { log_append(g_event_log, rec); }

inline void log_print_one_line(const EventRecord &r, Print &out) {
  out.print("EVT ");
  out.print(r.seq);
  out.print(" t=");
  out.print(r.t_ms);
  out.print(" type=");
  out.print(event_type_str(r.type));
  out.print(" st=");
  out.print((unsigned)r.fsm_state);
  out.print(" fl=");
  out.print((unsigned)r.flags);
  out.print(" a_rms=");
  out.print(r.audio_rms);
  out.print(" a_pk=");
  out.print(r.audio_peak);
  out.print(" zcr=");
  out.print((unsigned)r.audio_zcr_q15);
  out.print(" hfe=");
  out.print((unsigned)r.audio_hfe);
  out.print(" amag_mg=");
  out.print(r.accel_mag_mg);
  out.print(" apeak_mg=");
  out.print(r.accel_peak_mg);
  out.print(" imp_mg=");
  out.print((unsigned)r.accel_impulse_mg);
  out.println();
}

inline void log_dump_serial(const EventLog &log, Print &out = Serial) {
  out.println("--- EVENT LOG DUMP ---");
  out.print("count=");
  out.print(log.count);
  out.print(" cap=");
  out.print((unsigned)RAMPART_EVENT_LOG_CAPACITY);
  out.println();

  // Oldest-first traversal.
  uint16_t start = 0;
  if (log.count == (uint16_t)RAMPART_EVENT_LOG_CAPACITY) {
    start = log.head;
  }
  for (uint16_t i = 0; i < log.count; ++i) {
    uint16_t idx = (uint16_t)((start + i) % (uint16_t)RAMPART_EVENT_LOG_CAPACITY);
    log_print_one_line(log.buf[idx], out);
  }
  out.println("--- END DUMP ---");
}

inline void log_dump_serial() { log_dump_serial(g_event_log, Serial); }

