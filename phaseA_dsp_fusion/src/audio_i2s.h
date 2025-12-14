// Audio input adapter: I2S mic (real) or synthetic generator (mock).
#pragma once

#include <Arduino.h>

#include "config.h"

struct AudioFrame {
  static const size_t kSamples = (size_t)RAMPART_AUDIO_FRAME_SAMPLES;
  int16_t samples[kSamples];
  uint32_t t_ms;  // approximate capture timestamp (ms)
};

// Initializes audio capture or mock generator.
bool audio_init();

// Produces exactly one fixed-size frame.
// Returns true on success.
bool audio_read_frame(AudioFrame &out);

uint32_t audio_sample_rate_hz();
