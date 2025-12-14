#include "dsp_features.h"

#include <math.h>

namespace {

static float fast_sqrtf(float x) { return sqrtf(x); }

static float absf(float x) { return (x < 0.0f) ? -x : x; }

}  // namespace

void audio_compute_features(const int16_t *samples, size_t n, uint32_t /*sample_rate_hz*/,
                            AudioFeatures &out) {
  if (samples == nullptr || n < 2) {
    out = AudioFeatures{};
    return;
  }

  // RMS + peak.
  double sum_sq = 0.0;
  int16_t peak = 0;
  uint32_t zc = 0;
  double hfe_sum = 0.0;

  int16_t prev = samples[0];
  peak = (int16_t)abs(prev);

  for (size_t i = 0; i < n; ++i) {
    const int16_t s = samples[i];
    const int32_t si = (int32_t)s;
    sum_sq += (double)si * (double)si;
    const int16_t a = (int16_t)abs(si);
    if (a > peak) peak = a;

    if (i > 0) {
      // Zero-crossing rate.
      if ((prev < 0 && s >= 0) || (prev >= 0 && s < 0)) zc++;
      // High-frequency energy proxy = first difference energy.
      const int32_t d = (int32_t)s - (int32_t)prev;
      hfe_sum += (double)d * (double)d;
      prev = s;
    }
  }

  const float mean_sq = (float)(sum_sq / (double)n);
  out.rms = fast_sqrtf(mean_sq);
  out.peak = (float)peak;
  out.zcr = (float)zc / (float)(n - 1);
  out.hfe = (float)(hfe_sum / (double)(n - 1));

  out.trig_loud = (out.rms >= RAMPART_AUDIO_RMS_TRIG) || (out.peak >= RAMPART_AUDIO_PEAK_TRIG);
  out.trig_hf = (out.hfe >= RAMPART_AUDIO_HFE_TRIG);
}

void accel_feature_state_init(AccelFeatureState &st) {
  st.baseline_mag_g = 1.0f;
  st.prev_mag_g = 1.0f;
  st.peak_delta_g = 0.0f;
  st.peak_decay_ms = 0;
  st.initialized = false;
}

void accel_compute_features(const AccelSample &s, AccelFeatureState &st, AccelFeatures &out) {
  const float mag = fast_sqrtf(s.x_g * s.x_g + s.y_g * s.y_g + s.z_g * s.z_g);

  if (!st.initialized) {
    st.baseline_mag_g = mag;
    st.prev_mag_g = mag;
    st.peak_delta_g = 0.0f;
    st.peak_decay_ms = s.t_ms;
    st.initialized = true;
  }

  // Delta from baseline (captures movement / impact).
  const float delta = absf(mag - st.baseline_mag_g);

  // Impulse score: magnitude delta between samples (jerk-ish proxy).
  const float impulse = absf(mag - st.prev_mag_g);
  st.prev_mag_g = mag;

  // Peak delta tracking with decay.
  if (delta > st.peak_delta_g) {
    st.peak_delta_g = delta;
    st.peak_decay_ms = s.t_ms;
  } else {
    // Simple decay: if no new peak for 500ms, decay toward current delta.
    if ((uint32_t)(s.t_ms - st.peak_decay_ms) > 500u) {
      st.peak_delta_g *= 0.90f;
      if (st.peak_delta_g < delta) st.peak_delta_g = delta;
      st.peak_decay_ms = s.t_ms;
    }
  }

  // Baseline tracks slowly, but freeze during obvious impacts.
  const bool impact_candidate = (delta > (RAMPART_ACCEL_DELTA_G_TRIG * 0.5f)) ||
                                (impulse > (RAMPART_ACCEL_IMPULSE_G_TRIG * 0.5f));
  if (!impact_candidate) {
    const float alpha = 0.01f;
    st.baseline_mag_g = (1.0f - alpha) * st.baseline_mag_g + alpha * mag;
  }

  out.mag_g = mag;
  out.delta_mag_g = delta;
  out.peak_delta_g = st.peak_delta_g;
  out.impulse_g = impulse;
  out.impact = (delta >= RAMPART_ACCEL_DELTA_G_TRIG) || (impulse >= RAMPART_ACCEL_IMPULSE_G_TRIG);
}
