#include "BlePresence.h"
#include <NimBLEDevice.h>
#include "RampartLog.h"

static const char* kServiceUuid = "9f1c2b3a-2a4d-4f1b-9c5f-0b3d1a9c6f21";
static const char* kPresenceCharUuid = "9f1c2b3b-2a4d-4f1b-9c5f-0b3d1a9c6f21";

static BlePresence* g_self = nullptr;

class RampartServerCallbacks : public NimBLEServerCallbacks {
  void onConnect(NimBLEServer* pServer) override {
    (void)pServer;
    if (g_self) g_self->setOwnerPresentInternal(true);
  }

  void onDisconnect(NimBLEServer* pServer) override {
    if (g_self) g_self->setOwnerPresentInternal(false);

    if (pServer) {
      NimBLEDevice::startAdvertising();
      RampartLog::logf("BLE", "advertising restarted");
    }
  }
};

const char* BlePresence::serviceUuid() { return kServiceUuid; }
const char* BlePresence::presenceCharUuid() { return kPresenceCharUuid; }

void BlePresence::setOwnerPresenceChangedCallback(OwnerPresenceChangedFn fn, void* ctx) {
  m_cb = fn;
  m_cbCtx = ctx;
}

void BlePresence::setOwnerPresentInternal(bool present) {
  if (m_ownerPresent == present) return;
  m_ownerPresent = present;

  RampartLog::logf("BLE", "connected=%d", present ? 1 : 0);

  if (m_presenceChar) {
    auto* ch = static_cast<NimBLECharacteristic*>(m_presenceChar);
    ch->setValue((uint8_t)(present ? 1 : 0));
  }

  if (m_cb) m_cb(present, m_cbCtx);
}

bool BlePresence::begin(const char* deviceName) {
  g_self = this;
  m_ownerPresent = false;

  NimBLEDevice::init(deviceName ? deviceName : "RAMPART");
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);

  // No pairing/bonding; presence is “connected == owner present”.
  NimBLEDevice::setSecurityAuth(false, false, false);

  NimBLEServer* server = NimBLEDevice::createServer();
  if (!server) { RampartLog::logf("BLE", "init failed: createServer null"); return false; }
  server->setCallbacks(new RampartServerCallbacks());

  NimBLEService* service = server->createService(kServiceUuid);
  if (!service) { RampartLog::logf("BLE", "init failed: createService null"); return false; }

  NimBLECharacteristic* ch = service->createCharacteristic(
    kPresenceCharUuid,
    NIMBLE_PROPERTY::READ
  );
  if (ch) {
    ch->setValue((uint8_t)0);
    m_presenceChar = ch;
  }

  service->start();

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->addServiceUUID(kServiceUuid);
  adv->setScanResponse(true);
  adv->start();

  RampartLog::logf("BLE", "initialized stack=NimBLE-Arduino name=%s service=%s",
                   deviceName ? deviceName : "RAMPART",
                   kServiceUuid);
  RampartLog::logf("BLE", "advertising started");

  return true;
}
