// Fixed-size append-only event log with ring-buffer semantics.
//
// Hard requirements:
// - Minimal EventRecord + EventType enum
// - Append-only fixed-size ring buffer
// - log_init(), log_append(const EventRecord&), log_dump_serial()

#pragma once

#include <Arduino.h>

#include "event_canonical.h"

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

  // Evidence reference (in-memory ring buffers).
  uint32_t evidence_id;
  uint16_t audio_frames;
  uint16_t accel_samples;
  uint16_t audio_start_idx;
  uint16_t accel_start_idx;

  // Tamper-evident hash chaining (per-boot).
  uint64_t boot_id;
  uint64_t prev_hash;
  uint64_t hash;

  // Snapshot of select features (scaled).
  int16_t audio_rms;
  int16_t audio_peak;
  uint16_t audio_zcr_q15;
  uint16_t audio_hfe;

  int16_t accel_mag_mg;
  int16_t accel_peak_mg;
  uint16_t accel_impulse_mg;
};

// FNV-1a 64-bit helper.
// Seed is the starting hash value, allowing incremental hashing.
static inline uint64_t fnv1a64(const void *data, size_t len, uint64_t seed) {
  static constexpr uint64_t kFnvPrime = 1099511628211ull;
  uint64_t h = seed;
  const uint8_t *p = (const uint8_t *)data;
  for (size_t i = 0; i < len; ++i) {
    h ^= (uint64_t)p[i];
    h *= kFnvPrime;
  }
  return h;
}

// Canonical record hash. Ordering is explicit and stable.
// MUST include boot_id and prev_hash, MUST NOT include hash.
static inline uint64_t event_hash(const EventRecord &r) {
  static constexpr uint64_t kFnvOffsetBasis = 14695981039346656037ull;

  // Build signing-ready canonical integer record from EventRecord.
  // Note: EventRecord fields may be a subset; missing canonical fields are
  // filled deterministically.
  CanonicalEvent ce{};
  ce.boot_id = r.boot_id;
  ce.prev_hash = r.prev_hash;
  ce.seq = r.seq;
  ce.monotonic_ms = (uint64_t)r.t_ms;
  ce.event_type = (uint8_t)r.type;
  ce.confidence_0_100 = 0;  // EventRecord currently does not carry confidence.
  ce.src_flags = r.flags;

  // Audio feature snapshots.
  ce.audio_rms_q15 = r.audio_rms;
  ce.audio_hi_q15 = (int16_t)r.audio_hfe;
  ce.audio_zcr_q15 = (int16_t)r.audio_zcr_q15;
  ce.audio_peak_q15 = r.audio_peak;

  // Accel feature snapshots.
  ce.accel_mag_mg = r.accel_mag_mg;
  ce.accel_peak_mg = r.accel_peak_mg;
  ce.accel_impulse_q15 = (int16_t)r.accel_impulse_mg;

  // Evidence reference.
  ce.evidence_id = r.evidence_id;
  ce.audio_frames = r.audio_frames;
  ce.accel_samples = r.accel_samples;

  uint8_t buf[kCanonicalEventSerializedLen];
  const size_t n = serialize_canonical_event(buf, sizeof(buf), ce);
  return fnv1a64(buf, n, kFnvOffsetBasis);
}

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

  // Hash chain: previous hash is the last stored record's hash (or 0 if empty).
  rec.prev_hash = 0;
  if (log.count > 0) {
    const uint16_t cap = (uint16_t)RAMPART_EVENT_LOG_CAPACITY;
    const uint16_t last_idx = (uint16_t)((log.head + cap - 1u) % cap);
    rec.prev_hash = log.buf[last_idx].hash;
  }
  rec.hash = event_hash(rec);

  log.buf[log.head] = rec;
  log.head = (uint16_t)((log.head + 1u) % (uint16_t)RAMPART_EVENT_LOG_CAPACITY);
  if (log.count < (uint16_t)RAMPART_EVENT_LOG_CAPACITY) {
    log.count++;
  }
}

inline void log_append(const EventRecord &rec) { log_append(g_event_log, rec); }

inline void log_print_one_line(const EventRecord &r, Print &out) {
  auto print_hex_u64 = [&](uint64_t v) {
    static const char kHex[] = "0123456789abcdef";
    char buf[16];
    for (int i = 15; i >= 0; --i) {
      buf[i] = kHex[(uint8_t)(v & 0xFu)];
      v >>= 4;
    }
    out.print("0x");
    for (int i = 0; i < 16; ++i) out.print(buf[i]);
  };

  out.print("EVT ");
  out.print(r.seq);
  out.print(" prev=");
  print_hex_u64(r.prev_hash);
  out.print(" hash=");
  print_hex_u64(r.hash);
  out.print(" t=");
  out.print(r.t_ms);
  out.print(" type=");
  out.print(event_type_str(r.type));
  out.print(" st=");
  out.print((unsigned)r.fsm_state);
  out.print(" fl=");
  out.print((unsigned)r.flags);
  out.print(" evid=");
  out.print((unsigned long)r.evidence_id);
  out.print(" afr=");
  out.print((unsigned)r.audio_frames);
  out.print(" as=");
  out.print((unsigned)r.accel_samples);
  out.print(" aidx=");
  out.print((unsigned)r.audio_start_idx);
  out.print(" gidx=");
  out.print((unsigned)r.accel_start_idx);
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
