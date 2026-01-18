#include "StateMachine.h"
#include "RampartLog.h"

void StateMachine::begin(bool ownerPresentInitial) {
  m_ownerPresent = ownerPresentInitial;
  applyOwnerPresenceLocked();
}

const char* StateMachine::stateName(StateMachine::State s) {
  switch (s) {
    case State::ARMED: return "ARMED";
    case State::DISARMED: return "DISARMED";
    default: return "UNKNOWN";
  }
}

void StateMachine::setOwnerPresent(bool present) {
  if (m_ownerPresent == present) return;
  m_ownerPresent = present;
  applyOwnerPresenceLocked();
}

void StateMachine::applyOwnerPresenceLocked() {
  const State prev = m_state;
  m_state = m_ownerPresent ? State::DISARMED : State::ARMED;

  if (m_state != prev) {
    RampartLog::logf("ARM", "OWNER_PRESENT=%d; STATE=%s",
                     m_ownerPresent ? 1 : 0,
                     stateName(m_state));
  }
}
