// In-memory evidence capture buffers (audio frames + accel samples).
//
// These are standalone fixed-size ring buffers intended to provide a stable
// reference window (pre + post) around an emitted event. Evidence is referenced
// by an evidence_id that is stored in the EventRecord.
//
// Constraints:
// - No heap churn (fixed storage).
// - Deterministic behavior.
// - N_RING is sized so that capturing (pre + post) will not overwrite the
//   referenced window while post-capture is in progress.

#pragma once

#include <stdint.h>
#include <string.h>

#include "config.h"
#include "dsp_features.h"  // AccelSample

namespace rampart {

static inline uint16_t ring_sub(uint16_t head, uint16_t sub, uint16_t ring) {
  // (head - sub) mod ring
  return (uint16_t)((head + ring - (sub % ring)) % ring);
}

struct AudioEvidenceRef {
  uint32_t evidence_id;
  uint16_t start_idx;  // ring index of first frame in window
  uint16_t frames;     // frames in window
};

struct AccelEvidenceRef {
  uint32_t evidence_id;
  uint16_t start_idx;  // ring index of first sample in window
  uint16_t samples;    // samples in window
};

// Fixed ring-buffer of audio frames with freeze(begin)+post-capture semantics.
class AudioEvidenceBuffer {
 public:
  static constexpr uint16_t kFrameSamples = (uint16_t)RAMPART_AUDIO_FRAME_SAMPLES;
  static constexpr uint16_t kPre = (uint16_t)EVID_AUDIO_PRE_FRAMES;
  static constexpr uint16_t kPost = (uint16_t)EVID_AUDIO_POST_FRAMES;
  static constexpr uint16_t kRing = (uint16_t)(kPre + kPost + 1u);

  void init() {
    head_ = 0;
    count_ = 0;
    capturing_ = false;
    ready_ = false;
    frozen_id_ = 0;
    frozen_start_ = 0;
    frozen_frames_ = 0;
    post_remaining_ = 0;
  }

  void push_frame(const int16_t *frame) {
    memcpy(frames_[head_], frame, sizeof(frames_[head_]));
    head_ = (uint16_t)((head_ + 1u) % kRing);
    if (count_ < kRing) count_++;

    if (capturing_ && post_remaining_ > 0u) {
      post_remaining_--;
      if (post_remaining_ == 0u) {
        capturing_ = false;
        ready_ = true;
      }
    }
  }

  // Begins a capture window around the current head (most recently pushed
  // frames are the "pre" portion; upcoming pushes satisfy the "post" portion).
  AudioEvidenceRef freeze_begin(uint32_t evidence_id) {
    frozen_id_ = evidence_id;
    ready_ = (kPost == 0u);
    capturing_ = (kPost != 0u);
    post_remaining_ = kPost;

    const uint16_t actual_pre = (count_ < kPre) ? count_ : kPre;
    frozen_frames_ = (uint16_t)(actual_pre + kPost);
    frozen_start_ = ring_sub(head_, actual_pre, kRing);

    return get_ref();
  }

  // Included for symmetry with the task requirements. Post capture progresses
  // as frames are pushed; this just finalizes if the post portion has completed.
  void tick_post_capture() {
    if (capturing_ && post_remaining_ == 0u) {
      capturing_ = false;
      ready_ = true;
    }
  }

  AudioEvidenceRef get_ref() const {
    return AudioEvidenceRef{frozen_id_, frozen_start_, frozen_frames_};
  }

  bool ready() const { return ready_; }

  // Optional accessors for future evidence retrieval/debug.
  const int16_t *frame_at(uint16_t ring_idx) const { return frames_[ring_idx % kRing]; }

 private:
  int16_t frames_[kRing][kFrameSamples];
  uint16_t head_ = 0;   // next write index
  uint16_t count_ = 0;  // frames written since boot (clamped to kRing)

  bool capturing_ = false;
  bool ready_ = false;
  uint32_t frozen_id_ = 0;
  uint16_t frozen_start_ = 0;
  uint16_t frozen_frames_ = 0;
  uint16_t post_remaining_ = 0;
};

// Fixed ring-buffer of accel samples with the same freeze(begin)+post-capture.
class AccelEvidenceBuffer {
 public:
  static constexpr uint16_t kPre = (uint16_t)EVID_ACCEL_PRE_SAMPLES;
  static constexpr uint16_t kPost = (uint16_t)EVID_ACCEL_POST_SAMPLES;
  static constexpr uint16_t kRing = (uint16_t)(kPre + kPost + 1u);

  void init() {
    head_ = 0;
    count_ = 0;
    capturing_ = false;
    ready_ = false;
    frozen_id_ = 0;
    frozen_start_ = 0;
    frozen_samples_ = 0;
    post_remaining_ = 0;
  }

  void push_sample(const AccelSample &s) {
    samples_[head_] = s;
    head_ = (uint16_t)((head_ + 1u) % kRing);
    if (count_ < kRing) count_++;

    if (capturing_ && post_remaining_ > 0u) {
      post_remaining_--;
      if (post_remaining_ == 0u) {
        capturing_ = false;
        ready_ = true;
      }
    }
  }

  AccelEvidenceRef freeze_begin(uint32_t evidence_id) {
    frozen_id_ = evidence_id;
    ready_ = (kPost == 0u);
    capturing_ = (kPost != 0u);
    post_remaining_ = kPost;

    const uint16_t actual_pre = (count_ < kPre) ? count_ : kPre;
    frozen_samples_ = (uint16_t)(actual_pre + kPost);
    frozen_start_ = ring_sub(head_, actual_pre, kRing);

    return get_ref();
  }

  void tick_post_capture() {
    if (capturing_ && post_remaining_ == 0u) {
      capturing_ = false;
      ready_ = true;
    }
  }

  AccelEvidenceRef get_ref() const {
    return AccelEvidenceRef{frozen_id_, frozen_start_, frozen_samples_};
  }

  bool ready() const { return ready_; }
  const AccelSample &sample_at(uint16_t ring_idx) const { return samples_[ring_idx % kRing]; }

 private:
  AccelSample samples_[kRing];
  uint16_t head_ = 0;
  uint16_t count_ = 0;

  bool capturing_ = false;
  bool ready_ = false;
  uint32_t frozen_id_ = 0;
  uint16_t frozen_start_ = 0;
  uint16_t frozen_samples_ = 0;
  uint16_t post_remaining_ = 0;
};

}  // namespace rampart

