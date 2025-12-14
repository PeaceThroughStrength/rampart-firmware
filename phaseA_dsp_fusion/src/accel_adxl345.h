// ADXL345 accelerometer adapter: real I2C + mock generator.
#pragma once

#include <Arduino.h>

#include "config.h"
#include "dsp_features.h"  // AccelSample

bool accel_init();

// Read one sample (x/y/z in g). Returns true if updated.
bool accel_read_sample(AccelSample &out);
