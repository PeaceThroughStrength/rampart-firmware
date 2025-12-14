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

// ================================
// Rampart internal pin macro mapping
// (Drivers use RAMPART_* names)
// ================================
#define RAMPART_I2C_SDA_PIN   PIN_I2C_SDA
#define RAMPART_I2C_SCL_PIN   PIN_I2C_SCL

#define RAMPART_I2S_BCLK_PIN  PIN_I2S_BCLK
#define RAMPART_I2S_WS_PIN    PIN_I2S_WS
#define RAMPART_I2S_DIN_PIN   PIN_I2S_DIN

#define RAMPART_SIREN_PIN     PIN_SIREN_OUT

// ================================
// Rampart internal pin macro mapping
// (Drivers use RAMPART_* names)
// ================================
#define RAMPART_I2C_SDA_PIN   PIN_I2C_SDA
#define RAMPART_I2C_SCL_PIN   PIN_I2C_SCL

#define RAMPART_I2S_BCLK_PIN  PIN_I2S_BCLK
#define RAMPART_I2S_WS_PIN    PIN_I2S_WS
#define RAMPART_I2S_DIN_PIN   PIN_I2S_DIN

#define RAMPART_SIREN_PIN     PIN_SIREN_OUT
