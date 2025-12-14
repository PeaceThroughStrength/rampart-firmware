// Feature extraction for audio frames and accelerometer samples.
#pragma once

#include <Arduino.h>

#include "config.h"

struct AudioFeatures {
  float rms;
  float peak;
  float zcr;  // 0..1
  float hfe;  // high-frequency energy proxy

  bool trig_loud;
  bool trig_hf;
};

struct AccelSample {
  float x_g;
  float y_g;
  float z_g;
  uint32_t t_ms;
};

struct AccelFeatures {
  float mag_g;
  float delta_mag_g;
  float peak_delta_g;
  float impulse_g;
  bool impact;
};

struct AccelFeatureState {
  float baseline_mag_g;
  float prev_mag_g;
  float peak_delta_g;
  uint32_t peak_decay_ms;
  bool initialized;
};

void audio_compute_features(const int16_t *samples, size_t n, uint32_t sample_rate_hz,
                            AudioFeatures &out);

void accel_feature_state_init(AccelFeatureState &st);
void accel_compute_features(const AccelSample &s, AccelFeatureState &st, AccelFeatures &out);
