#pragma once

// ================================
// ESP32-S3-DevKitC-1 PIN DEFINITIONS
// ================================

// -------- I2C (ADXL345) ----------
#define PIN_I2C_SDA        8    // TODO: verify on board
#define PIN_I2C_SCL        9    // TODO: verify on board

// -------- I2S (AUDIO) ------------
#define PIN_I2S_BCLK       4    // TODO: verify
#define PIN_I2S_WS         5    // TODO: verify
#define PIN_I2S_DIN        6    // TODO: verify

// -------- SIREN / ACTUATOR -------
#define PIN_SIREN_OUT      7    // TODO: verify

// -------- STATUS LED -------------
#ifndef LED_BUILTIN
#define LED_BUILTIN        2
#endif
