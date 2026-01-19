#pragma once
#include <Arduino.h>

class StateMachine {
public:
  enum class State : uint8_t { ARMED = 0, DISARMED = 1 };

  void begin(bool ownerPresentInitial);
  void setOwnerPresent(bool present);

  bool isOwnerPresent() const { return m_ownerPresent; }
  bool isArmed() const { return m_state == State::ARMED; }
  State state() const { return m_state; }
  bool intrusionConfirmed() const { return m_intrusionConfirmed; }

  static const char* stateName(State s);

private:
  bool m_ownerPresent = false;
  State m_state = State::ARMED;
  bool m_intrusionConfirmed = false;

  void applyOwnerPresenceLocked();
};
