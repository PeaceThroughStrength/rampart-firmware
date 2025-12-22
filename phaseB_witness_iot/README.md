# Rampart Firmware

ESP32 firmware for Rampart devices.

## Phase B – Witness IoT
- MQTT → AWS IoT Core
- Monotonic device_seq
- NTP-synced event_time
- DEV_BYPASS crypto (Phase B only)

## Architecture
- ESP32-S3
- PubSubClient (MQTT)
- AWS IoT Core
- JSON event envelope

## Roadmap
- Phase C: ECDSA P-256 signing
- Phase D: Secure element (ATECC608)
- Phase E: Mirror-module integration
