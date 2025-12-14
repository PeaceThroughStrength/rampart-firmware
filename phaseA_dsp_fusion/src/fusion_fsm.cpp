#include "fusion_fsm.h"

#include "config.h"

namespace {

static uint16_t clamp_u16(int32_t v) {
  if (v < 0) return 0;
  if (v > 65535) return 65535;
  return (uint16_t)v;
}

static int16_t clamp_i16(int32_t v) {
  if (v > 32767) return 32767;
  if (v < -32768) return -32768;
  return (int16_t)v;
}

static uint16_t q15_from_unit(float x) {
  if (x <= 0.0f) return 0;
  if (x >= 1.0f) return 32767u;
  return (uint16_t)(x * 32767.0f);
}

static void fill_snapshot(EventRecord &e, const AudioFeatures &a, const AccelFeatures &g,
                          FusionState st, uint32_t now_ms) {
  e.t_ms = now_ms;
  e.fsm_state = (uint8_t)st;
  e.flags = 0;
  if (a.trig_loud) e.flags |= 0x01;
  if (a.trig_hf) e.flags |= 0x02;
  if (g.impact) e.flags |= 0x04;

  e.audio_rms = clamp_i16((int32_t)a.rms);
  e.audio_peak = clamp_i16((int32_t)a.peak);
  e.audio_zcr_q15 = q15_from_unit(a.zcr);
  e.audio_hfe = clamp_u16((int32_t)a.hfe);

  e.accel_mag_mg = clamp_i16((int32_t)(g.mag_g * 1000.0f));
  e.accel_peak_mg = clamp_i16((int32_t)(g.peak_delta_g * 1000.0f));
  e.accel_impulse_mg = clamp_u16((int32_t)(g.impulse_g * 1000.0f));
}

}  // namespace

const char *fsm_state_str(FusionState s) {
  switch (s) {
    case FusionState::DISARMED:
      return "DISARMED";
    case FusionState::ARMED_IDLE:
      return "ARMED_IDLE";
    case FusionState::SUSPECT:
      return "SUSPECT";
    case FusionState::COOLDOWN:
      return "COOLDOWN";
    default:
      return "?";
  }
}

void fsm_init(FusionContext &ctx) {
  ctx.state = FusionState::DISARMED;
  ctx.state_enter_ms = 0;
  ctx.suspect_start_ms = 0;
  ctx.last_audio_trig_ms = 0;
  ctx.last_accel_trig_ms = 0;
  ctx.cooldown_until_ms = 0;
}

bool fsm_tick(FusionContext &ctx, bool armed, uint32_t now_ms, const AudioFeatures &audio,
              const AccelFeatures &accel, EventRecord &out_event) {
  // Pure logic: fuse modalities.
  const bool audio_sus = audio.trig_loud && audio.trig_hf;
  const bool accel_sus = accel.impact;

  if (!armed) {
    // Force disarmed.
    if (ctx.state != FusionState::DISARMED) {
      ctx.state = FusionState::DISARMED;
      ctx.state_enter_ms = now_ms;
    }
    return false;
  }

  if (ctx.state == FusionState::DISARMED) {
    ctx.state = FusionState::ARMED_IDLE;
    ctx.state_enter_ms = now_ms;
  }

  switch (ctx.state) {
    case FusionState::ARMED_IDLE: {
      if (audio_sus && accel_sus) {
        // Immediate compound.
        fill_snapshot(out_event, audio, accel, ctx.state, now_ms);
        out_event.type = EventType::ALERT_FIRED;
        ctx.state = FusionState::COOLDOWN;
        ctx.state_enter_ms = now_ms;
        ctx.cooldown_until_ms = now_ms + RAMPART_FSM_SUPPRESSION_MS;
        return true;
      }

      if (audio_sus || accel_sus) {
        ctx.state = FusionState::SUSPECT;
        ctx.state_enter_ms = now_ms;
        ctx.suspect_start_ms = now_ms;
        if (audio_sus) ctx.last_audio_trig_ms = now_ms;
        if (accel_sus) ctx.last_accel_trig_ms = now_ms;

        fill_snapshot(out_event, audio, accel, ctx.state, now_ms);
        out_event.type = audio_sus ? EventType::AUDIO_SUSPECT : EventType::IMPACT_SUSPECT;
        return true;
      }
      return false;
    }

    case FusionState::SUSPECT: {
      if (audio_sus) ctx.last_audio_trig_ms = now_ms;
      if (accel_sus) ctx.last_accel_trig_ms = now_ms;

      const bool have_audio = (ctx.last_audio_trig_ms >= ctx.suspect_start_ms) &&
                              ((uint32_t)(now_ms - ctx.last_audio_trig_ms) <=
                               RAMPART_FSM_CORRELATION_WINDOW_MS);
      const bool have_accel = (ctx.last_accel_trig_ms >= ctx.suspect_start_ms) &&
                              ((uint32_t)(now_ms - ctx.last_accel_trig_ms) <=
                               RAMPART_FSM_CORRELATION_WINDOW_MS);
      const bool compound = have_audio && have_accel;

      if (compound) {
        fill_snapshot(out_event, audio, accel, ctx.state, now_ms);
        out_event.type = EventType::ALERT_FIRED;
        ctx.state = FusionState::COOLDOWN;
        ctx.state_enter_ms = now_ms;
        ctx.cooldown_until_ms = now_ms + RAMPART_FSM_SUPPRESSION_MS;
        return true;
      }

      // Single-modality sustain.
      if ((uint32_t)(now_ms - ctx.suspect_start_ms) >= RAMPART_FSM_SINGLE_MODALITY_SUSTAIN_MS &&
          (audio_sus || accel_sus)) {
        fill_snapshot(out_event, audio, accel, ctx.state, now_ms);
        out_event.type = EventType::ALERT_FIRED;
        ctx.state = FusionState::COOLDOWN;
        ctx.state_enter_ms = now_ms;
        ctx.cooldown_until_ms = now_ms + RAMPART_FSM_SUPPRESSION_MS;
        return true;
      }

      // Timeout back to idle if no triggers observed.
      if (!audio_sus && !accel_sus &&
          (uint32_t)(now_ms - ctx.suspect_start_ms) > RAMPART_FSM_CORRELATION_WINDOW_MS) {
        ctx.state = FusionState::ARMED_IDLE;
        ctx.state_enter_ms = now_ms;
      }
      return false;
    }

    case FusionState::COOLDOWN: {
      if (now_ms >= ctx.cooldown_until_ms) {
        ctx.state = FusionState::ARMED_IDLE;
        ctx.state_enter_ms = now_ms;
        fill_snapshot(out_event, audio, accel, ctx.state, now_ms);
        out_event.type = EventType::ALERT_CLEARED;
        return true;
      }
      return false;
    }

    case FusionState::DISARMED:
    default:
      return false;
  }
}
