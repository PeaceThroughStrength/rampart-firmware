#pragma once
#include <Arduino.h>

class BlePresence {
public:
  using OwnerPresenceChangedFn = void (*)(bool present, void* ctx);

  void setOwnerPresenceChangedCallback(OwnerPresenceChangedFn fn, void* ctx);

  bool begin(const char* deviceName);
  bool isOwnerPresent() const { return m_ownerPresent; }

  static const char* serviceUuid();
  static const char* presenceCharUuid();

private:
  friend class RampartServerCallbacks;

  bool m_ownerPresent = false;
  void* m_presenceChar = nullptr; // NimBLECharacteristic* (opaque in header)

  OwnerPresenceChangedFn m_cb = nullptr;
  void* m_cbCtx = nullptr;

  void setOwnerPresentInternal(bool present);
};
