#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <time.h>
#include <Preferences.h>
#include "certs.h"

#define WIFI_SSID     "Paddington"
#define WIFI_PASS     "avilondon"
#define AWS_ENDPOINT  "a2va1jm3kt4kp4-ats.iot.us-west-2.amazonaws.com"
#define DEVICE_ID     "RAMPART-DEV-LIVE"
#define CLIENT_ID     "RAMPART-DEV-LIVE"
#define MQTT_TOPIC    "pts/iot-core/dev/RAMPART-DEV-LIVE/001/event"
#define TRIGGER_PIN   14

WiFiClientSecure net;
PubSubClient mqtt(net);

Preferences prefs;
static uint32_t g_device_seq = 0;


// UUIDv4 generator (ESP32: uses hardware RNG via esp_random())
static String uuidV4() {
  uint8_t b[16];
  for (int i = 0; i < 16; i += 4) {
    uint32_t r = (uint32_t)esp_random();
    b[i + 0] = (uint8_t)(r >> 24);
    b[i + 1] = (uint8_t)(r >> 16);
    b[i + 2] = (uint8_t)(r >> 8);
    b[i + 3] = (uint8_t)(r >> 0);
  }

  // Set version (4) and variant (10)
  b[6] = (b[6] & 0x0F) | 0x40;
  b[8] = (b[8] & 0x3F) | 0x80;

  char out[37];
  snprintf(
    out, sizeof(out),
    "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
    b[0], b[1], b[2], b[3],
    b[4], b[5],
    b[6], b[7],
    b[8], b[9],
    b[10], b[11], b[12], b[13], b[14], b[15]
  );
  return String(out);
}

static void syncTime() {
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  Serial0.print("NTP Syncing");
  int tries = 0;
  while (time(nullptr) < 1700000000 && tries < 40) { delay(500); Serial0.print("."); tries++; }
  Serial0.println(time(nullptr) < 1700000000 ? " FAIL" : " OK");
}

static void connectMqtt() {
  net.setCACert(AWS_ROOT_CA);
  net.setCertificate(AWS_CERT);
  net.setPrivateKey(AWS_PRIVATE_KEY);
  mqtt.setServer(AWS_ENDPOINT, 8883);

  mqtt.setBufferSize(1024);
  Serial0.println("Connecting to AWS IoT...");
  if (mqtt.connect(CLIENT_ID)) {
    Serial0.println("CONNECTED (GREEN)");
    neopixelWrite(RGB_BUILTIN, 0, 255, 0);
  } else {
    Serial0.printf("FAILED, state=%d", mqtt.state());
    neopixelWrite(RGB_BUILTIN, 255, 0, 0);
  }
}

void setup() {
  Serial0.begin(115200);
  delay(1500);
  Serial0.println("=== RAMPART PHASEB BOOT ===");
  Serial0.printf("RESET_REASON=%d\n", esp_reset_reason());
  Serial0.printf("BUILD: %s %s\n", __DATE__, __TIME__);
  Serial0.printf("MQTT_TOPIC: %s\n", MQTT_TOPIC);
  Serial0.flush();

  prefs.begin("rampart", false);
  g_device_seq = prefs.getUInt("device_seq", 0);
  Serial0.printf("SEQ_LOADED=%lu\n", (unsigned long)g_device_seq);

  pinMode(TRIGGER_PIN, INPUT);
  neopixelWrite(RGB_BUILTIN, 255, 0, 255); // Boot = Purple

  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial0.println("WiFi CONNECTING...");
  while (WiFi.status() != WL_CONNECTED) { delay(200); }
  Serial0.println("WiFi OK");

  syncTime();
  connectMqtt();
}

void loop() {
  if (!mqtt.connected()) connectMqtt();
  mqtt.loop();

  // Pin Status Debugger (2 Hz)
  static uint32_t lastLog = 0;
  if (millis() - lastLog > 500) {
    lastLog = millis();
}

  // Edge-triggered publish (LOW->HIGH) + cooldown to avoid spam
  static int lastPin = LOW;
  static uint32_t lastPublishMs = 0;
  const uint32_t COOLDOWN_MS = 5000;

  int pin = digitalRead(TRIGGER_PIN);
  bool rising = (lastPin == LOW && pin == HIGH);
  lastPin = pin;

  if (rising && (millis() - lastPublishMs) >= COOLDOWN_MS) {
    lastPublishMs = millis();

    const unsigned long now_s = (unsigned long)time(nullptr);
    g_device_seq++;
    prefs.putUInt("device_seq", g_device_seq);
    String event_id = uuidV4();

    String payload = "{";
    payload += "\"v\":1,";
    payload += "\"schema_version\":1,";
    payload += "\"device_id\":\"" DEVICE_ID "\",";
    payload += "\"backend_id\":\"dev\",";
    payload += "\"fw_version\":\"dev\",";
    payload += "\"event_type\":\"MOTION_DETECTED\",";
    payload += "\"event_time\":" + String(now_s) + ",";
    payload += "\"device_seq\":" + String(g_device_seq) + ",";
    payload += "\"nonce\":\"n-" + String(g_device_seq) + "\",";
    payload += "\"crypto\":{";
    payload += "\"alg\":\"DEV_BYPASS\",";
    payload += "\"sig\":\"DEV_BYPASS\",";
    payload += "\"pubkey_fingerprint\":\"DEV_BYPASS\",";
    payload += "\"pubkey\":\"DEV_BYPASS\"},";
    payload += "\"event_id\":\"" + event_id + "\",";
    payload += "\"evidence\":{\"kind\":\"MOTION\",\"sensor\":\"PIR\",\"raw_hash\":\"abababababababababababababababababababababababababababababababab\"}";
    payload += "}";
Serial0.println("Publishing Event...");
if (mqtt.publish(MQTT_TOPIC, payload.c_str())) {
      Serial0.println("SENT: " + payload);
      neopixelWrite(RGB_BUILTIN, 0, 0, 255); // Blue flash
      delay(200);
      neopixelWrite(RGB_BUILTIN, 0, 255, 0);
    } else {
      Serial0.println("PUBLISH_FAIL");
      neopixelWrite(RGB_BUILTIN, 255, 0, 0);
      delay(200);
      neopixelWrite(RGB_BUILTIN, 0, 255, 0);
    }
  }
}
