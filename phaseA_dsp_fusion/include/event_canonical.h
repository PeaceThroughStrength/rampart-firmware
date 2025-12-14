#pragma once

#include <stddef.h>
#include <stdint.h>

// Signing-ready canonical event representation.
// - Integer-only fields (stable across compilers / float repr)
// - Explicit field order for serialization
struct CanonicalEvent {
  uint64_t boot_id;
  uint64_t prev_hash;
  uint32_t seq;
  uint64_t monotonic_ms;
  uint8_t event_type;
  uint8_t confidence_0_100;
  uint8_t src_flags;
  int16_t audio_rms_q15;
  int16_t audio_hi_q15;
  int16_t audio_zcr_q15;
  int16_t audio_peak_q15;
  int16_t accel_mag_mg;
  int16_t accel_peak_mg;
  int16_t accel_impulse_q15;
  uint32_t evidence_id;
  uint16_t audio_frames;
  uint16_t accel_samples;
};

static constexpr size_t kCanonicalEventSerializedLen = 53u;

static inline int16_t clamp_i16(int32_t v) {
  if (v < -32768) return (int16_t)-32768;
  if (v > 32767) return (int16_t)32767;
  return (int16_t)v;
}

static inline int16_t q15_from_float(float x, float max_abs) {
  if (!(max_abs > 0.0f)) return 0;
  // Clamp to [-max_abs, +max_abs].
  if (x > max_abs) x = max_abs;
  if (x < -max_abs) x = -max_abs;

  // Map to Q15 with symmetric scaling. Note: +max_abs => +32767.
  const float scale = 32767.0f / max_abs;
  const float scaled = x * scale;
  // Round-to-nearest without pulling in heavier libm variants.
  const int32_t v = (int32_t)(scaled + (scaled >= 0.0f ? 0.5f : -0.5f));
  return clamp_i16(v);
}

static inline int16_t mg_from_g(float g) {
  // Convert g -> milli-g, clamp to int16.
  const float mg_f = g * 1000.0f;
  const int32_t mg = (int32_t)(mg_f + (mg_f >= 0.0f ? 0.5f : -0.5f));
  return clamp_i16(mg);
}

static inline void write_u16_le(uint8_t *out, uint16_t v) {
  out[0] = (uint8_t)(v & 0xFFu);
  out[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static inline void write_u32_le(uint8_t *out, uint32_t v) {
  out[0] = (uint8_t)(v & 0xFFu);
  out[1] = (uint8_t)((v >> 8) & 0xFFu);
  out[2] = (uint8_t)((v >> 16) & 0xFFu);
  out[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static inline void write_u64_le(uint8_t *out, uint64_t v) {
  out[0] = (uint8_t)(v & 0xFFull);
  out[1] = (uint8_t)((v >> 8) & 0xFFull);
  out[2] = (uint8_t)((v >> 16) & 0xFFull);
  out[3] = (uint8_t)((v >> 24) & 0xFFull);
  out[4] = (uint8_t)((v >> 32) & 0xFFull);
  out[5] = (uint8_t)((v >> 40) & 0xFFull);
  out[6] = (uint8_t)((v >> 48) & 0xFFull);
  out[7] = (uint8_t)((v >> 56) & 0xFFull);
}

static inline void write_i16_le(uint8_t *out, int16_t v) {
  write_u16_le(out, (uint16_t)v);
}

static inline size_t serialize_canonical_event(uint8_t *out, size_t out_len,
                                               const CanonicalEvent &e) {
  if (!out || out_len < kCanonicalEventSerializedLen) return 0;

  size_t o = 0;
  write_u64_le(out + o, e.boot_id);
  o += 8;
  write_u64_le(out + o, e.prev_hash);
  o += 8;
  write_u32_le(out + o, e.seq);
  o += 4;
  write_u64_le(out + o, e.monotonic_ms);
  o += 8;

  out[o++] = e.event_type;
  out[o++] = e.confidence_0_100;
  out[o++] = e.src_flags;

  write_i16_le(out + o, e.audio_rms_q15);
  o += 2;
  write_i16_le(out + o, e.audio_hi_q15);
  o += 2;
  write_i16_le(out + o, e.audio_zcr_q15);
  o += 2;
  write_i16_le(out + o, e.audio_peak_q15);
  o += 2;

  write_i16_le(out + o, e.accel_mag_mg);
  o += 2;
  write_i16_le(out + o, e.accel_peak_mg);
  o += 2;
  write_i16_le(out + o, e.accel_impulse_q15);
  o += 2;

  write_u32_le(out + o, e.evidence_id);
  o += 4;
  write_u16_le(out + o, e.audio_frames);
  o += 2;
  write_u16_le(out + o, e.accel_samples);
  o += 2;

  return o;
}

