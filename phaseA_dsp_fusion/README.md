# Phase A DSP + Fusion (ESP32-S3 / Arduino / PlatformIO)

This firmware project is a self-contained **DSP + sensor fusion prototype** for Rampart Phase A.

Hard requirements met by default:

- Compiles with `pio run` **without hardware connected**.
- Defaults to **mock sensors** via `#define RAMPART_USE_MOCKS 1` in [`include/config.h`](include/config.h).
- Real codepaths (I2S + ADXL345) exist behind `#if !RAMPART_USE_MOCKS` and compile.

## Build

```bash
cd rampart-firmware/phaseA_dsp_fusion
pio run
```

Optional monitor:

```bash
pio device monitor
```

## What it does

- **Audio frames**: fixed-size `int16_t` frames (default 512 samples @ 16 kHz).
- **Audio features**: RMS, peak, ZCR, and a high-frequency energy proxy.
- **Accel samples**: ADXL345 (real) or mock generator.
- **Accel features**: magnitude, delta-from-baseline, peak delta, impulse score and `impact` boolean.
- **Fusion FSM**: pure logic state machine that emits one-line events when suspicious/alert states occur.
- **Event log**: append-only fixed-size ring buffer; dumpable over Serial.

## Serial output + commands

Serial is `115200`.

You will see:

- `init ... OK/FAIL` for module init status
- `SUM ...` once per second with feature values and FSM state
- `EVT ...` one-line event records on event emission

Commands:

- `d` — dump event log
- `a` — toggle `armed` (starts **true** by default)
- `t` — emit a `TEST` event

## Mocks

When `RAMPART_USE_MOCKS=1`, audio and accel generate **random-ish bursts every ~10–20 seconds**, with a shared burst scheduler that makes events **sometimes correlated**.

## Real hardware skeletons

When `RAMPART_USE_MOCKS=0`:

- Audio uses ESP32 I2S driver init/read skeleton in [`src/audio_i2s.cpp`](src/audio_i2s.cpp)
- Accelerometer uses `Wire` with ADXL345 DEVID `0xE5`, sets measurement mode, reads XYZ and converts to g in [`src/accel_adxl345.cpp`](src/accel_adxl345.cpp)

Pin constants and thresholds live in [`include/config.h`](include/config.h).
