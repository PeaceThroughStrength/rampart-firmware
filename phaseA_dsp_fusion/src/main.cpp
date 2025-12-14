#include <Arduino.h>

#if defined(ESP32)
#include <esp_system.h>
#endif

#include "accel_adxl345.h"
#include "audio_i2s.h"
#include "config.h"
#include "dsp_features.h"
#include "evidence_buffers.h"
#include "event_log.h"
#include "fusion_fsm.h"

// Required global instances for header-only event_log.
EventLog g_event_log;

#if RAMPART_USE_MOCKS
RampartMockCorrelation g_rampart_mock_corr;
#endif

namespace {

static uint64_t g_boot_id = 0;
static uint32_t g_next_evidence_id = 1;

static rampart::AudioEvidenceBuffer g_audio_evid;
static rampart::AccelEvidenceBuffer g_accel_evid;

static uint64_t make_boot_id() {
#if defined(ESP32)
  // Prefer ESP HW RNG when available.
  const uint64_t hi = ((uint64_t)esp_random()) << 32;
  const uint64_t lo = (uint64_t)esp_random();
  uint64_t id = hi | lo;
  if (id == 0) id = 1;
  return id;
#else
  // Fallback for non-ESP builds.
  uint64_t id = ((uint64_t)micros() << 32) ^ (uint64_t)millis();
  if (id == 0) id = 1;
  return id;
#endif
}

static uint32_t frame_period_ms() {
  return (uint32_t)((1000ull * (uint64_t)RAMPART_AUDIO_FRAME_SAMPLES) /
                    (uint64_t)RAMPART_AUDIO_SAMPLE_RATE_HZ);
}

static void emit_and_print(EventRecord &e) {
  // Ensure every emitted record carries this boot identity.
  e.boot_id = g_boot_id;
  log_append(e);

  // Print the actual stored record (seq/prev_hash/hash are assigned in log_append).
  const uint16_t cap = (uint16_t)RAMPART_EVENT_LOG_CAPACITY;
  const uint16_t last_idx = (uint16_t)((g_event_log.head + cap - 1u) % cap);
  log_print_one_line(g_event_log.buf[last_idx], Serial);
}

static void attach_evidence(EventRecord &e) {
  const uint32_t evid = g_next_evidence_id++;
  const rampart::AudioEvidenceRef ar = g_audio_evid.freeze_begin(evid);
  const rampart::AccelEvidenceRef gr = g_accel_evid.freeze_begin(evid);

  e.evidence_id = evid;
  e.audio_frames = ar.frames;
  e.audio_start_idx = ar.start_idx;
  e.accel_samples = gr.samples;
  e.accel_start_idx = gr.start_idx;
}

}  // namespace

void setup() {
  Serial.begin(115200);
  delay(200);

  Serial.println();
  Serial.println("Rampart PhaseA DSP+Fusion (ESP32-S3 Arduino)");
  Serial.print("RAMPART_USE_MOCKS=");
  Serial.println((int)RAMPART_USE_MOCKS);

  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, LOW);

  g_boot_id = make_boot_id();

  g_audio_evid.init();
  g_accel_evid.init();

  log_init();

#if RAMPART_USE_MOCKS
  g_rampart_mock_corr.seed = 0xC0FFEEu;
  g_rampart_mock_corr.next_burst_ms = 10000u;
  g_rampart_mock_corr.burst_end_ms = 0u;
  g_rampart_mock_corr.correlated = true;
#endif

  const bool audio_ok = audio_init();
  const bool accel_ok = accel_init();

  Serial.print("init audio=");
  Serial.print(audio_ok ? "OK" : "FAIL");
  Serial.print(" accel=");
  Serial.println(accel_ok ? "OK" : "FAIL");

  EventRecord boot{};
  boot.type = EventType::BOOT;
  boot.t_ms = millis();
  boot.fsm_state = 0;
  attach_evidence(boot);
  emit_and_print(boot);
}

void loop() {
  const uint32_t now_ms = millis();

  static bool armed = true;  // hard requirement: armed true by default.

  // Serial command handling.
  while (Serial.available() > 0) {
    const char c = (char)Serial.read();
    if (c == 'd' || c == 'D') {
      log_dump_serial();
    } else if (c == 'a' || c == 'A') {
      armed = !armed;
      EventRecord e{};
      e.type = EventType::ARMED_CHANGED;
      e.t_ms = now_ms;
      e.flags = armed ? 1 : 0;
      attach_evidence(e);
      emit_and_print(e);
      Serial.print("armed=");
      Serial.println(armed ? "true" : "false");
    } else if (c == 't' || c == 'T') {
      EventRecord e{};
      e.type = EventType::TEST;
      e.t_ms = now_ms;
      attach_evidence(e);
      emit_and_print(e);
    }
  }

  // Module states.
  static FusionContext fsm;
  static bool fsm_inited = false;
  static AccelFeatureState accel_state;
  static bool feature_inited = false;

  if (!fsm_inited) {
    fsm_init(fsm);
    fsm_inited = true;
  }
  if (!feature_inited) {
    accel_feature_state_init(accel_state);
    feature_inited = true;
  }

  static AudioFeatures audio_feat{};
  static AccelFeatures accel_feat{};

  // Audio scheduling.
  static uint32_t next_audio_ms = 0;
  if (now_ms >= next_audio_ms) {
    AudioFrame frame;
    if (audio_read_frame(frame)) {
      g_audio_evid.push_frame(frame.samples);
      audio_compute_features(frame.samples, AudioFrame::kSamples, audio_sample_rate_hz(),
                             audio_feat);
    }
    next_audio_ms = now_ms + frame_period_ms();
  }

  // Accel scheduling.
  static uint32_t next_accel_ms = 0;
  const uint32_t accel_period_ms = (uint32_t)(1000u / RAMPART_ACCEL_RATE_HZ);
  if (now_ms >= next_accel_ms) {
    AccelSample s;
    if (accel_read_sample(s)) {
      g_accel_evid.push_sample(s);
      accel_compute_features(s, accel_state, accel_feat);
    }
    next_accel_ms = now_ms + accel_period_ms;
  }

  // FSM tick.
  EventRecord evt{};
  if (fsm_tick(fsm, armed, now_ms, audio_feat, accel_feat, evt)) {
    attach_evidence(evt);
    emit_and_print(evt);
  }

  // Advance post-capture state machines.
  g_audio_evid.tick_post_capture();
  g_accel_evid.tick_post_capture();

  // Periodic feature summary.
  static uint32_t next_print_ms = 0;
  if (now_ms >= next_print_ms) {
    next_print_ms = now_ms + RAMPART_PRINT_INTERVAL_MS;

    Serial.print("SUM t=");
    Serial.print(now_ms);
    Serial.print(" armed=");
    Serial.print(armed ? 1 : 0);
    Serial.print(" st=");
    Serial.print(fsm_state_str(fsm.state));

    Serial.print(" a_rms=");
    Serial.print(audio_feat.rms, 1);
    Serial.print(" a_pk=");
    Serial.print(audio_feat.peak, 0);
    Serial.print(" a_zcr=");
    Serial.print(audio_feat.zcr, 3);
    Serial.print(" a_hfe=");
    Serial.print(audio_feat.hfe, 0);

    Serial.print(" g_d=");
    Serial.print(accel_feat.delta_mag_g, 3);
    Serial.print(" g_pk=");
    Serial.print(accel_feat.peak_delta_g, 3);
    Serial.print(" g_imp=");
    Serial.print(accel_feat.impulse_g, 3);
    Serial.print(" impact=");
    Serial.print(accel_feat.impact ? 1 : 0);

    Serial.println();

    // Heartbeat LED.
    static bool led = false;
    led = !led;
    digitalWrite(LED_BUILTIN, led ? HIGH : LOW);
  }
}
