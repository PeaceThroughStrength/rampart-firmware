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
  x ^= (x << 13);
  x ^= (x >> 17);
  x ^= (x << 5);
  return x;
}

static int16_t clamp_i16(int32_t v) {
  if (v > 32767) return 32767;
  if (v < -32768) return -32768;
  return (int16_t)v;
}

static bool in_corr_burst(uint32_t now_ms) {
  if (now_ms < g_rampart_mock_corr.burst_end_ms) return true;
  if (now_ms < g_rampart_mock_corr.next_burst_ms) return false;

  // Schedule next correlated burst.
  uint32_t r = xorshift32(g_rampart_mock_corr.seed);
  uint32_t gap = 10000u + (r % 10001u);  // 10-20s
  uint32_t dur = 250u + ((r >> 16) % 451u);  // 250-700ms

  g_rampart_mock_corr.correlated = ((r & 0x3u) != 0);  // 75%
  g_rampart_mock_corr.next_burst_ms = now_ms + gap;
  g_rampart_mock_corr.burst_end_ms = now_ms + dur;
  return true;
}

static bool in_audio_local_burst(uint32_t now_ms) {
  static uint32_t seed = 0xA011234u;
  static uint32_t next_ms = 7000;
  static uint32_t end_ms = 0;
  if (now_ms < end_ms) return true;
  if (now_ms < next_ms) return false;
  uint32_t r = xorshift32(seed);
  uint32_t gap = 10000u + (r % 10001u);
  uint32_t dur = 120u + ((r >> 16) % 401u);
  next_ms = now_ms + gap;
  end_ms = now_ms + dur;
  return true;
}

static void gen_mock_audio(AudioFrame &out) {
  const uint32_t now_ms = millis();
  const bool corr = in_corr_burst(now_ms) && g_rampart_mock_corr.correlated;
  const bool local = in_audio_local_burst(now_ms);
  const bool burst = corr || local;

  static uint32_t seed = 0x13579BDFu;
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
