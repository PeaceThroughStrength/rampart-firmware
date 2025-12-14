#include "accel_adxl345.h"

#include <Wire.h>

namespace {

#if RAMPART_USE_MOCKS
static uint32_t xorshift32(uint32_t &x) {
  x ^= (x << 13);
  x ^= (x >> 17);
  x ^= (x << 5);
  return x;
}

static bool in_accel_local_burst(uint32_t now_ms) {
  static uint32_t seed = 0xACCEBEEFu;
  static uint32_t next_ms = 9000;
  static uint32_t end_ms = 0;
  if (now_ms < end_ms) return true;
  if (now_ms < next_ms) return false;
  uint32_t r = xorshift32(seed);
  uint32_t gap = 10000u + (r % 10001u);
  uint32_t dur = 80u + ((r >> 16) % 260u);  // 80-340ms
  next_ms = now_ms + gap;
  end_ms = now_ms + dur;
  return true;
}

static bool in_corr_burst(uint32_t now_ms) {
  return (now_ms < g_rampart_mock_corr.burst_end_ms) && g_rampart_mock_corr.correlated;
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
  static uint32_t seed = 0x2468ACE0u;
  const bool burst = in_corr_burst(now_ms) || in_accel_local_burst(now_ms);

  // Gravity + small noise.
  uint32_t r = xorshift32(seed);
  float nx = ((int32_t)(r & 0xFF) - 128) * 0.0008f;
  float ny = ((int32_t)((r >> 8) & 0xFF) - 128) * 0.0008f;
  float nz = ((int32_t)((r >> 16) & 0xFF) - 128) * 0.0008f;

  float x = nx;
  float y = ny;
  float z = 1.0f + nz;

  if (burst) {
    // Random-ish impacts: short impulses on x/y/z.
    const float amp = 0.10f + ((float)((r >> 24) & 0x7F) / 127.0f) * 0.90f;  // 0.1..1.0
    // Make it spiky: occasionally very sharp.
    const bool sharp = ((r & 0x7u) == 0);
    const float spike = sharp ? (amp * 2.0f) : amp;
    x += (((int)(r & 1u) ? 1.0f : -1.0f) * spike);
    y += (((int)(r & 2u) ? 1.0f : -1.0f) * (0.6f * spike));
    z += (((int)(r & 4u) ? 1.0f : -1.0f) * (0.4f * spike));
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
