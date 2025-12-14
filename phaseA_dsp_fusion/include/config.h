#include "board_pins_esp32s3_devkitc1.h"
// Rampart Phase A DSP + Fusion firmware configuration
//
// Hard requirement: default to mocks so `pio run` compiles/runs without hardware.
#pragma once

#include <stdint.h>

// ----------------------------
// Deterministic mock harness
// ----------------------------

// 1 = deterministic mock generators (fixed scheduling + seeded PRNG).
#ifndef RAMPART_DETERMINISTIC
#define RAMPART_DETERMINISTIC 1
#endif

// Base seed for deterministic mock PRNG streams.
#ifndef RAMPART_MOCK_SEED
#define RAMPART_MOCK_SEED 0xC0FFEEu
#endif

enum MockScenario {
  SCN_AUDIO_ONLY = 1,
  SCN_ACCEL_ONLY = 2,
  SCN_CORRELATED = 3,
  SCN_UNCORRELATED = 4,
};

// Compile-time default mock scenario.
#ifndef RAMPART_MOCK_SCENARIO
#define RAMPART_MOCK_SCENARIO SCN_CORRELATED
#endif

// Expected outcomes over the self-test window (see main.cpp).
// Interpreted as minimum required counts unless explicitly checked for == 0.
#if (RAMPART_MOCK_SCENARIO == SCN_AUDIO_ONLY)
  #define EXPECT_AUDIO_EVENTS 2u
  #define EXPECT_ACCEL_EVENTS 0u
  #define EXPECT_CORR_EVENTS 0u
#elif (RAMPART_MOCK_SCENARIO == SCN_ACCEL_ONLY)
  #define EXPECT_AUDIO_EVENTS 0u
  #define EXPECT_ACCEL_EVENTS 2u
  #define EXPECT_CORR_EVENTS 0u
#elif (RAMPART_MOCK_SCENARIO == SCN_CORRELATED)
  #define EXPECT_AUDIO_EVENTS 2u
  #define EXPECT_ACCEL_EVENTS 2u
  #define EXPECT_CORR_EVENTS 2u
#elif (RAMPART_MOCK_SCENARIO == SCN_UNCORRELATED)
  #define EXPECT_AUDIO_EVENTS 2u
  #define EXPECT_ACCEL_EVENTS 2u
  #define EXPECT_CORR_EVENTS 0u
#else
  #define EXPECT_AUDIO_EVENTS 0u
  #define EXPECT_ACCEL_EVENTS 0u
  #define EXPECT_CORR_EVENTS 0u
#endif

// 1 = mock audio + mock accel generators.
// 0 = real I2S + real ADXL345 (skeletons compile; runtime requires hardware).
#ifndef RAMPART_USE_MOCKS
#define RAMPART_USE_MOCKS 1
#endif

// ----------------------------
// General
// ----------------------------

// Serial feature summary cadence.
#ifndef RAMPART_PRINT_INTERVAL_MS
#define RAMPART_PRINT_INTERVAL_MS 1000u
#endif

// ----------------------------
// Audio (I2S + DSP)
// ----------------------------

#ifndef RAMPART_AUDIO_SAMPLE_RATE_HZ
#define RAMPART_AUDIO_SAMPLE_RATE_HZ 16000u
#endif

// Keep this power-of-two-ish for DSP simplicity.
#ifndef RAMPART_AUDIO_FRAME_SAMPLES
#define RAMPART_AUDIO_FRAME_SAMPLES 512u
#endif

// Trigger thresholds (tune later).
// Units are in raw sample amplitude for peak/RMS and proxy energy for HFE.
#ifndef RAMPART_AUDIO_RMS_TRIG
#define RAMPART_AUDIO_RMS_TRIG 1100.0f
#endif

#ifndef RAMPART_AUDIO_PEAK_TRIG
#define RAMPART_AUDIO_PEAK_TRIG 6000.0f
#endif

// High-frequency energy proxy threshold (mean squared first-difference).
#ifndef RAMPART_AUDIO_HFE_TRIG
#define RAMPART_AUDIO_HFE_TRIG 3500000.0f
#endif

// ----------------------------
// Accelerometer (ADXL345)
// ----------------------------

#ifndef RAMPART_ACCEL_RATE_HZ
#define RAMPART_ACCEL_RATE_HZ 80u
#endif

// Thresholds for impact detection.
#ifndef RAMPART_ACCEL_DELTA_G_TRIG
#define RAMPART_ACCEL_DELTA_G_TRIG 0.25f
#endif

#ifndef RAMPART_ACCEL_IMPULSE_G_TRIG
#define RAMPART_ACCEL_IMPULSE_G_TRIG 0.18f
#endif

// ----------------------------
// Fusion FSM timings
// ----------------------------

#ifndef RAMPART_FSM_CORRELATION_WINDOW_MS
#define RAMPART_FSM_CORRELATION_WINDOW_MS 1000u
#endif

#ifndef RAMPART_FSM_SINGLE_MODALITY_SUSTAIN_MS
#define RAMPART_FSM_SINGLE_MODALITY_SUSTAIN_MS 400u
#endif

#ifndef RAMPART_FSM_SUPPRESSION_MS
#define RAMPART_FSM_SUPPRESSION_MS 10000u
#endif

// ----------------------------
// Hardware pins / bus settings (real path)
// ----------------------------

// ESP32-S3 I2S pins (adjust for your wiring)
#ifndef RAMPART_I2S_BCLK_PIN
#define RAMPART_I2S_BCLK_PIN 5
#endif

#ifndef RAMPART_I2S_WS_PIN
#define RAMPART_I2S_WS_PIN 6
#endif

#ifndef RAMPART_I2S_DIN_PIN
#define RAMPART_I2S_DIN_PIN 4
#endif

// ADXL345 I2C (adjust for your wiring)
#ifndef RAMPART_I2C_SDA_PIN
#define RAMPART_I2C_SDA_PIN 8
#endif

#ifndef RAMPART_I2C_SCL_PIN
#define RAMPART_I2C_SCL_PIN 9
#endif

#ifndef RAMPART_ADXL345_I2C_ADDR
#define RAMPART_ADXL345_I2C_ADDR 0x53
#endif

// ----------------------------
// Evidence capture (in-memory ring buffers)
// ----------------------------

// Audio evidence window sizes (frames).
#ifndef EVID_AUDIO_PRE_FRAMES
#define EVID_AUDIO_PRE_FRAMES 8u
#endif

#ifndef EVID_AUDIO_POST_FRAMES
#define EVID_AUDIO_POST_FRAMES 8u
#endif

// Accel evidence window sizes (samples).
#ifndef EVID_ACCEL_PRE_SAMPLES
#define EVID_ACCEL_PRE_SAMPLES 40u
#endif

#ifndef EVID_ACCEL_POST_SAMPLES
#define EVID_ACCEL_POST_SAMPLES 40u
#endif

// ----------------------------
// Mocks: correlated burst scheduler
// ----------------------------

#if RAMPART_USE_MOCKS
struct RampartMockCorrelation {
  uint32_t seed;
  uint32_t next_burst_ms;
  uint32_t burst_end_ms;
  bool correlated;
};

// Defined in main.cpp when mocks are enabled.
extern RampartMockCorrelation g_rampart_mock_corr;
#endif
