#include "accel_adxl345.h"

#include "config.h"

#include <Wire.h>

namespace {

#if RAMPART_USE_MOCKS
static uint32_t xorshift32(uint32_t &x) {
  // NOTE: state must never be 0.
  x ^= (x << 13);
  x ^= (x >> 17);
  x ^= (x << 5);
  return x;
}

static uint32_t prng_seed_stream(uint32_t stream_id) {
  uint32_t s = (uint32_t)RAMPART_MOCK_SEED ^ stream_id;
  if (s == 0u) s = 1u;
  xorshift32(s);
  return s;
}

static bool mock_accel_impulse_active(uint32_t now_ms) {
#if !RAMPART_DETERMINISTIC
  (void)now_ms;
  return false;
#else
  // Deterministic, fixed schedule.
  // Keep impulse duration < RAMPART_FSM_SINGLE_MODALITY_SUSTAIN_MS so ACCEL_ONLY
  // doesn't produce single-modality alerts.
  static constexpr uint32_t kAudioPhaseMs = 2000u;
  static constexpr uint32_t kPeriodMs = 12000u;
  static constexpr uint32_t kImpulseMs = 60u;

  if (RAMPART_MOCK_SCENARIO == SCN_AUDIO_ONLY) return false;

  uint32_t phase_ms = 2500u;  // default for ACCEL_ONLY
  if (RAMPART_MOCK_SCENARIO == SCN_CORRELATED) {
    // Aligned within correlation window of the audio burst.
    phase_ms = kAudioPhaseMs + 500u;
  } else if (RAMPART_MOCK_SCENARIO == SCN_UNCORRELATED) {
    // Always outside correlation window.
    phase_ms = kAudioPhaseMs + RAMPART_FSM_CORRELATION_WINDOW_MS + 500u;
  }

  if (now_ms < phase_ms) return false;
  const uint32_t dt = (uint32_t)((now_ms - phase_ms) % kPeriodMs);
  return (dt < kImpulseMs);
#endif
}

#endif

// ADXL345 registers.
static const uint8_t REG_DEVID = 0x00;
static const uint8_t REG_POWER_CTL = 0x2D;
static const uint8_t REG_DATA_FORMAT = 0x31;
static const uint8_t REG_DATAX0 = 0x32;

static bool i2c_write_reg(uint8_t addr, uint8_t reg, uint8_t val) {
  Wire.beginTransmission(addr);
  Wire.write(reg);
  Wire.write(val);
  return (Wire.endTransmission() == 0);
}

static bool i2c_read_regs(uint8_t addr, uint8_t reg, uint8_t *buf, size_t n) {
  Wire.beginTransmission(addr);
  Wire.write(reg);
  if (Wire.endTransmission(false) != 0) return false;
  size_t got = Wire.requestFrom((int)addr, (int)n);
  if (got != n) return false;
  for (size_t i = 0; i < n; ++i) {
    buf[i] = (uint8_t)Wire.read();
  }
  return true;
}

}  // namespace

bool accel_init() {
#if RAMPART_USE_MOCKS
  return true;
#else
  Wire.begin((int)RAMPART_I2C_SDA_PIN, (int)RAMPART_I2C_SCL_PIN);

  uint8_t devid = 0;
  if (!i2c_read_regs((uint8_t)RAMPART_ADXL345_I2C_ADDR, REG_DEVID, &devid, 1)) return false;
  if (devid != 0xE5) return false;

  // DATA_FORMAT: FULL_RES=1, range=16g (0b11)
  if (!i2c_write_reg((uint8_t)RAMPART_ADXL345_I2C_ADDR, REG_DATA_FORMAT, 0x0B)) return false;
  // POWER_CTL: MEASURE=1
  if (!i2c_write_reg((uint8_t)RAMPART_ADXL345_I2C_ADDR, REG_POWER_CTL, 0x08)) return false;
  return true;
#endif
}

bool accel_read_sample(AccelSample &out) {
  const uint32_t now_ms = millis();

#if RAMPART_USE_MOCKS
  static uint32_t seed = 0;
  if (seed == 0u) seed = prng_seed_stream(0xACC310u);

  const bool impulse = mock_accel_impulse_active(now_ms);

  // Gravity + small noise.
  uint32_t r = xorshift32(seed);
  float nx = ((int32_t)(r & 0xFF) - 128) * 0.0008f;
  float ny = ((int32_t)((r >> 8) & 0xFF) - 128) * 0.0008f;
  float nz = ((int32_t)((r >> 16) & 0xFF) - 128) * 0.0008f;

  float x = nx;
  float y = ny;
  float z = 1.0f + nz;

  if (impulse) {
    // Deterministic impact: a short, high-amplitude impulse to reliably exceed
    // RAMPART_ACCEL_IMPULSE_G_TRIG.
    // Alternate sign based on the current sample time to increase the impulse score.
    const uint32_t sample_period_ms = (uint32_t)(1000u / RAMPART_ACCEL_RATE_HZ);
    const float sgn = (((now_ms / sample_period_ms) & 1u) != 0u) ? 1.0f : -1.0f;
    const float spike = 2.0f;
    x += sgn * spike;
    y += -sgn * (0.7f * spike);
    z += sgn * (0.3f * spike);
  }

  out.x_g = x;
  out.y_g = y;
  out.z_g = z;
  out.t_ms = now_ms;
  return true;
#else
  uint8_t raw[6];
  if (!i2c_read_regs((uint8_t)RAMPART_ADXL345_I2C_ADDR, REG_DATAX0, raw, sizeof(raw))) {
    return false;
  }
  int16_t x = (int16_t)((raw[1] << 8) | raw[0]);
  int16_t y = (int16_t)((raw[3] << 8) | raw[2]);
  int16_t z = (int16_t)((raw[5] << 8) | raw[4]);

  // FULL_RES scale ~ 3.9 mg/LSB.
  const float g_per_lsb = 0.0039f;
  out.x_g = (float)x * g_per_lsb;
  out.y_g = (float)y * g_per_lsb;
  out.z_g = (float)z * g_per_lsb;
  out.t_ms = now_ms;
  return true;
#endif
}
