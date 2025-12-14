#include "audio_i2s.h"

#include "config.h"

#if !RAMPART_USE_MOCKS
  #include <driver/i2s.h>
#endif

namespace {

static uint32_t s_frame_counter = 0;

#if RAMPART_USE_MOCKS

static uint32_t xorshift32(uint32_t &x) {
  // xorshift32 PRNG: deterministic, cheap.
  // NOTE: state must never be 0.
  x ^= (x << 13);
  x ^= (x >> 17);
  x ^= (x << 5);
  return x;
}

static uint32_t prng_seed_stream(uint32_t stream_id) {
  uint32_t s = (uint32_t)RAMPART_MOCK_SEED ^ stream_id;
  if (s == 0u) s = 1u;
  // One warm-up round to diffuse the seed a bit.
  xorshift32(s);
  return s;
}

static int16_t clamp_i16(int32_t v) {
  if (v > 32767) return 32767;
  if (v < -32768) return -32768;
  return (int16_t)v;
}

static bool mock_audio_burst_active(uint32_t now_ms) {
#if !RAMPART_DETERMINISTIC
  (void)now_ms;
  return false;
#else
  // Deterministic, fixed schedule.
  // Keep burst duration < RAMPART_FSM_SINGLE_MODALITY_SUSTAIN_MS so single-modality
  // alerts don't fire in AUDIO_ONLY/UNCORRELATED scenarios.
  static constexpr uint32_t kAudioPhaseMs = 2000u;
  static constexpr uint32_t kAudioPeriodMs = 12000u;
  static constexpr uint32_t kAudioBurstMs = 200u;

  if (RAMPART_MOCK_SCENARIO == SCN_ACCEL_ONLY) return false;
  if (now_ms < kAudioPhaseMs) return false;
  const uint32_t dt = (uint32_t)((now_ms - kAudioPhaseMs) % kAudioPeriodMs);
  return (dt < kAudioBurstMs);
#endif
}

static void gen_mock_audio(AudioFrame &out) {
  const uint32_t now_ms = millis();
  const bool burst = mock_audio_burst_active(now_ms);

  static uint32_t seed = 0;
  if (seed == 0u) seed = prng_seed_stream(0xA0D010u);
  const uint32_t frame_start_sample = s_frame_counter * (uint32_t)RAMPART_AUDIO_FRAME_SAMPLES;
  const uint32_t sr = RAMPART_AUDIO_SAMPLE_RATE_HZ;

  // Base noise + occasional burst: high-frequency-ish square wave + impulse.
  for (size_t i = 0; i < AudioFrame::kSamples; ++i) {
    uint32_t r = xorshift32(seed);
    int32_t noise = (int32_t)((int16_t)(r & 0x3FF)) - 512;  // [-512..511]
    int32_t s = noise;

    if (burst) {
      // High-frequency proxy: alternate sign at ~4kHz and add a short impulse at burst onset.
      const uint32_t t = frame_start_sample + (uint32_t)i;
      const uint32_t phase = (t * 4000u) / sr;
      const int32_t sq = (phase & 1u) ? 1 : -1;
      const int32_t hf = sq * (int32_t)(2500 + (r & 0x3FF));
      s += hf;

      if (i < 8) {
        // Short impulse at the beginning of a frame while in burst.
        s += (int32_t)(9000 - (int32_t)i * 900);
      }
    }

    out.samples[i] = clamp_i16(s);
  }

  // Timestamp approximated by frame counter.
  const uint32_t frame_ms = (uint32_t)((1000ull * (uint64_t)RAMPART_AUDIO_FRAME_SAMPLES) /
                                       (uint64_t)RAMPART_AUDIO_SAMPLE_RATE_HZ);
  out.t_ms = now_ms + (s_frame_counter * frame_ms);
}

#endif

}  // namespace

bool audio_init() {
  s_frame_counter = 0;

#if RAMPART_USE_MOCKS
  return true;
#else
  // Minimal I2S init skeleton (compiles; intended for later wiring).
  // Using I2S0 in RX mode.
  const i2s_port_t port = I2S_NUM_0;
  i2s_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.mode = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_RX);
  cfg.sample_rate = (int)RAMPART_AUDIO_SAMPLE_RATE_HZ;
  cfg.bits_per_sample = I2S_BITS_PER_SAMPLE_16BIT;
  cfg.channel_format = I2S_CHANNEL_FMT_ONLY_LEFT;
  cfg.communication_format = I2S_COMM_FORMAT_STAND_I2S;
  cfg.intr_alloc_flags = 0;
  cfg.dma_buf_count = 4;
  cfg.dma_buf_len = (int)RAMPART_AUDIO_FRAME_SAMPLES;
  cfg.use_apll = false;
  cfg.tx_desc_auto_clear = false;
  cfg.fixed_mclk = 0;

  i2s_pin_config_t pins;
  pins.bck_io_num = RAMPART_I2S_BCLK_PIN;
  pins.ws_io_num = RAMPART_I2S_WS_PIN;
  pins.data_out_num = -1;
  pins.data_in_num = RAMPART_I2S_DIN_PIN;

  esp_err_t e = i2s_driver_install(port, &cfg, 0, nullptr);
  if (e != ESP_OK) return false;
  e = i2s_set_pin(port, &pins);
  if (e != ESP_OK) return false;
  return true;
#endif
}

bool audio_read_frame(AudioFrame &out) {
  out.t_ms = millis();

#if RAMPART_USE_MOCKS
  gen_mock_audio(out);
  s_frame_counter++;
  return true;
#else
  // Real path: attempt to read exactly one frame. This will block briefly if hardware is present.
  size_t bytes_read = 0;
  const i2s_port_t port = I2S_NUM_0;
  esp_err_t e = i2s_read(port, (void *)out.samples,
                         (size_t)RAMPART_AUDIO_FRAME_SAMPLES * sizeof(int16_t), &bytes_read,
                         10 / portTICK_PERIOD_MS);
  if (e != ESP_OK) return false;
  if (bytes_read != (size_t)RAMPART_AUDIO_FRAME_SAMPLES * sizeof(int16_t)) return false;
  s_frame_counter++;
  return true;
#endif
}

uint32_t audio_sample_rate_hz() { return (uint32_t)RAMPART_AUDIO_SAMPLE_RATE_HZ; }
