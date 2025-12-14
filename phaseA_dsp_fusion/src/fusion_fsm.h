// Pure fusion FSM logic (no hardware calls).
#pragma once

#include <Arduino.h>

#include "dsp_features.h"
#include "event_log.h"

enum class FusionState : uint8_t {
  DISARMED = 0,
  ARMED_IDLE = 1,
  SUSPECT = 2,
  COOLDOWN = 3,
};

struct FusionContext {
  FusionState state;
  uint32_t state_enter_ms;

  uint32_t suspect_start_ms;
  uint32_t last_audio_trig_ms;
  uint32_t last_accel_trig_ms;

  uint32_t cooldown_until_ms;
};

void fsm_init(FusionContext &ctx);

// Returns true if an event should be logged/emitted.
bool fsm_tick(FusionContext &ctx, bool armed, uint32_t now_ms, const AudioFeatures &audio,
              const AccelFeatures &accel, EventRecord &out_event);

const char *fsm_state_str(FusionState s);
