#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <time.h>
#include <Preferences.h>

#include "BlePresence.h"
#include "RampartLog.h"
#include "StateMachine.h"

// Phase C: mbedTLS ECDSA P-256 signing (ESP32 built-in)
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha256.h"
#include "mbedtls/base64.h"
#include "mbedtls/error.h"
#include "certs.h"

#define WIFI_SSID     "Paddington"
#define WIFI_PASS     "avilondon"
#define AWS_ENDPOINT  "a2va1jm3kt4kp4-ats.iot.us-west-2.amazonaws.com"
#define DEVICE_ID     "RAMPART-DEV-LIVE"
#define CLIENT_ID     "RAMPART-DEV-LIVE"
#define MQTT_TOPIC    "pts/device/dev/RAMPART-DEV-LIVE/001/event"
#define TRIGGER_PIN   14

#ifndef RAMPART_FIRMWARE_VERSION
#define RAMPART_FIRMWARE_VERSION "phaseC_signed_iot-dev"
#endif

WiFiClientSecure net;
PubSubClient mqtt(net);

Preferences prefs;
static uint32_t g_device_seq = 0;

// Downlink / config state (demo-safe + auditable)
static String g_cmd_topic;
static bool g_manual_override = false;
static bool g_manual_armed = true;
static String g_config_version;

static BlePresence g_blePresence;
static StateMachine g_stateMachine;

// Forward declarations (helpers defined before their implementations)
static String uuidV4();
static bool rampart_sign_canonical_and_get_crypto_block(
  const String& canonical,
  String* out_sig_b64,
  String* out_pubkey_pem,
  String* out_pubkey_fingerprint_hex
);

static String rampart_derive_cmd_topic_from_event_topic(const char* event_topic_cstr) {
  String eventTopic = String(event_topic_cstr ? event_topic_cstr : "");
  const String suffix = "/event";
  if (eventTopic.endsWith(suffix)) {
    return eventTopic.substring(0, eventTopic.length() - suffix.length()) + "/cmd";
  }

  // Fallback (should not happen if MQTT_TOPIC is correctly formed)
  Serial0.printf("CMD_TOPIC_DERIVE_WARN: MQTT_TOPIC does not end with %s\n", suffix.c_str());
  return eventTopic + "/cmd";
}

static bool rampart_is_armed_effective() {
  return g_manual_override ? g_manual_armed : g_stateMachine.isArmed();
}

static void onOwnerPresenceChanged(bool present, void* ctx) {
  StateMachine* sm = (StateMachine*)ctx;
  if (!sm) return;
  sm->setOwnerPresent(present);
}


// Format ISO-8601 UTC string matching JS: new Date(sec*1000).toISOString() for whole-second epochs.
// Example: 2025-01-01T00:00:00.000Z
static void rampart_iso8601_utc_from_epoch(unsigned long epoch_s, char* out, size_t out_len) {
  time_t t = (time_t)epoch_s;
  struct tm tm_utc;
  gmtime_r(&t, &tm_utc);
  snprintf(
    out,
    out_len,
    "%04d-%02d-%02dT%02d:%02d:%02d.000Z",
    tm_utc.tm_year + 1900,
    tm_utc.tm_mon + 1,
    tm_utc.tm_mday,
    tm_utc.tm_hour,
    tm_utc.tm_min,
    tm_utc.tm_sec
  );
}

// Publish a signed event to MQTT_TOPIC with a variable event_type.
// Keeps canonical signing rules identical to the existing MOTION_DETECTED implementation.
// extra_fields_json must be either empty or a string starting with ',' containing valid JSON fields.
static bool rampart_publish_signed_event(
  const char* event_type,
  const char* evidence_status,
  const String& extra_fields_json,
  String* out_event_id
) {
  if (!event_type) return false;
  if (out_event_id) *out_event_id = "";

  const unsigned long now_s = (unsigned long)time(nullptr);
  char occurredAtIso[32];
  rampart_iso8601_utc_from_epoch(now_s, occurredAtIso, sizeof(occurredAtIso));

  g_device_seq++;
  prefs.putUInt("device_seq", g_device_seq);
  const String event_id = uuidV4();
  if (out_event_id) *out_event_id = event_id;

  // Canonical string for backend verification (exact bytes)
  // Order + keys must match rampart-protocol canonicalizeForSigning().
  String canonical = "{";
  canonical += "\"eventId\":\"" + event_id + "\",";
  canonical += "\"deviceSerial\":\"" DEVICE_ID "\",";
  canonical += "\"backendId\":\"dev\",";
  canonical += "\"eventType\":\"" + String(event_type) + "\",";
  canonical += "\"occurredAt\":\"" + String(occurredAtIso) + "\",";
  canonical += "\"firmwareVersion\":\"dev\",";
  canonical += "\"nonce\":\"n-" + String(g_device_seq) + "\"";
  canonical += "}";

  String sig_b64;
  String pubkey_pem;
  String pubkey_fp;
  bool sign_ok = rampart_sign_canonical_and_get_crypto_block(canonical, &sig_b64, &pubkey_pem, &pubkey_fp);
  if (!sign_ok) {
    // Safety behavior: if signing fails, DO NOT publish and flash LED RED.
    neopixelWrite(RGB_BUILTIN, 255, 0, 0);
    return false;
  }

  // JSON-safe embed of PEM (JSON string escape for newlines)
  String pubkey_json = pubkey_pem;
  pubkey_json.replace("\r", "");
  pubkey_json.replace("\n", "\\n");

  String payload = "{";
  payload += "\"v\":1,";
  payload += "\"schema_version\":1,";
  payload += "\"device_id\":\"" DEVICE_ID "\",";
  payload += "\"backend_id\":\"dev\",";
  payload += "\"fw_version\":\"dev\",";
  payload += "\"event_type\":\"" + String(event_type) + "\",";
  payload += "\"event_time\":" + String(now_s) + ",";
  payload += "\"device_seq\":" + String(g_device_seq) + ",";
  payload += "\"nonce\":\"n-" + String(g_device_seq) + "\",";
  payload += "\"crypto\":{";
  payload += "\"alg\":\"ECDSA_P256_SHA256_DER_B64\",";
  payload += "\"sig\":\"" + sig_b64 + "\",";
  payload += "\"pubkey\":\"" + pubkey_json + "\",";
  payload += "\"pubkey_fingerprint\":\"" + pubkey_fp + "\"},";
  payload += "\"event_id\":\"" + event_id + "\",";
  payload += "\"evidence\":{\"status\":\"" + String(evidence_status ? evidence_status : "") + "\",\"raw_hash\":\"abababababababababababababababababababababababababababababababab\"}";
  if (extra_fields_json.length() > 0) {
    payload += extra_fields_json;
  }
  payload += "}";

  Serial0.println("Publishing Event...");
  if (mqtt.publish(MQTT_TOPIC, payload.c_str())) {
    Serial0.println("SENT: " + payload);
    neopixelWrite(RGB_BUILTIN, 0, 0, 255); // Blue flash
    delay(200);
    neopixelWrite(RGB_BUILTIN, 0, 255, 0); // Green only after successful signed publish
    return true;
  }

  Serial0.println("PUBLISH_FAIL");
  neopixelWrite(RGB_BUILTIN, 255, 0, 0);
  // NOTE: do not flash GREEN after a failed publish
  return false;
}

static void rampart_publish_config_ack(const char* event_type, const String& cfg_version, const String& reason_opt) {
  String extra;
  if (cfg_version.length() > 0) {
    extra += ",\"config_version\":\"" + cfg_version + "\"";
  }
  if (reason_opt.length() > 0) {
    extra += ",\"reason\":\"" + reason_opt + "\"";
  }

  String event_id;
  const bool ok = rampart_publish_signed_event(event_type, event_type, extra, &event_id);
  if (ok) {
    Serial0.printf("ACK_PUB_OK event_id=%s event_type=%s\n", event_id.c_str(), event_type);
  } else {
    Serial0.printf("ACK_PUB_FAIL event_id=%s event_type=%s\n", event_id.c_str(), event_type);
  }
}

static void onMqttMessage(char* topic, byte* payload, unsigned int length) {
  Serial0.printf("CMD_RX topic=%s bytes=%u\n", topic ? topic : "(null)", (unsigned)length);

  // Raw payload visibility (first 300 bytes as printable ASCII, plus a short hex dump)
  // NOTE: do this BEFORE deserializeJson() so we can diagnose weird edge cases.
  Serial0.println("CMD_PAYLOAD_RAW_BEGIN");

  const unsigned int ascii_cap = 300u;
  const unsigned int ascii_len = (length < ascii_cap) ? length : ascii_cap;
  String ascii;
  ascii.reserve(ascii_len);
  for (unsigned int i = 0; i < ascii_len; i++) {
    const uint8_t b = payload[i];
    const char c = (b >= 0x20 && b <= 0x7E) ? (char)b : '.';
    ascii += c;
  }
  Serial0.println(ascii);

  const unsigned int hex_cap = 120u;
  const unsigned int hex_len = (length < hex_cap) ? length : hex_cap;
  char hex_line[241];
  for (unsigned int i = 0; i < hex_len; i++) {
    snprintf(&hex_line[i * 2], 3, "%02x", (unsigned int)payload[i]);
  }
  hex_line[hex_len * 2] = '\0';
  Serial0.println(hex_line);

  Serial0.println("CMD_PAYLOAD_RAW_END");

  StaticJsonDocument<1024> doc;
  DeserializationError err = deserializeJson(doc, payload, length);
  if (err) {
    Serial0.printf("CMD_JSON_FAIL err=%s\n", err.c_str());
    // For auditability: emit a CONFIG_REJECTED event with a reason.
    rampart_publish_config_ack("CONFIG_REJECTED", "", String("json_parse_fail:") + err.c_str());
    return;
  }
  String cmd = doc["cmd"] | String("");
  cmd.trim();
  if (cmd.length() == 0) {
    // Reveal the top-level JSON keys present to help diagnose shape mismatches.
    Serial0.print("CMD_KEYS: ");
    if (doc.is<JsonObject>()) {
      JsonObject obj = doc.as<JsonObject>();
      bool first = true;
      for (JsonPair kv : obj) {
        if (!first) Serial0.print(",");
        Serial0.print(kv.key().c_str());
        first = false;
      }
    }
    Serial0.println();
    Serial0.println("CMD_INVALID missing_cmd");
    return;
  }
  Serial0.printf("CMD=%s\n", cmd.c_str());

  if (cmd == "ARM") {
    g_manual_override = true;
    g_manual_armed = true;
    Serial0.println("ARM: manual_override=1 state=ARMED");
    return;
  }

  if (cmd == "DISARM") {
    g_manual_override = true;
    g_manual_armed = false;
    Serial0.println("ARM: manual_override=1 state=DISARMED");
    return;
  }

  if (cmd == "CLEAR_OVERRIDE") {
    g_manual_override = false;
    Serial0.println("ARM: manual_override=0 (BLE authoritative)");
    return;
  }

  if (cmd == "APPLY_CONFIG") {
    String cfgv = doc["config_version"] | String("");
    cfgv.trim();
    if (cfgv.length() == 0 && doc.containsKey("version")) {
      int v = doc["version"] | 0;
      if (v > 0) cfgv = String(v);
    }
    if (cfgv.length() == 0) {
      rampart_publish_config_ack("CONFIG_REJECTED", "", "missing_config_version");
      return;
    }

    // Minimal stub: persist config_version as the applied config.
    g_config_version = cfgv;
    prefs.putString("config_version", g_config_version);

    // As requested: APPLY_CONFIG clears manual override.
    g_manual_override = false;

    rampart_publish_config_ack("CONFIG_APPLIED", g_config_version, "");
    return;
  }

  if (cmd == "SIMULATE_SIGNAL") {
    const char* signal = doc["signal"] | "MOTION";
    Serial0.printf("SIMULATE_SIGNAL signal=%s\n", signal);

    // Demo-safe behavior: simulate only explicit, deterministic signals.
    if (strcmp(signal, "MOTION") == 0) {
      (void)rampart_publish_signed_event("MOTION_DETECTED", "SIMULATED", "", nullptr);
    } else if (strcmp(signal, "GLASS_BREAK") == 0) {
      (void)rampart_publish_signed_event("GLASS_BREAK_DETECTED", "SIMULATED", "", nullptr);
    } else if (strcmp(signal, "PRESSURE") == 0) {
      (void)rampart_publish_signed_event("PRESSURE_DETECTED", "SIMULATED", "", nullptr);
    } else {
      Serial0.printf("SIMULATE_SIGNAL unknown_signal=%s\n", signal);
    }
    return;
  }

  // Demo push validation: allow a manual siren trigger over MQTT.
  // Emits signed events so backend ingest + push allowlist can be exercised end-to-end.
  if (cmd == "SIREN_ON") {
    Serial0.println("SIREN_ON: publish event");
    (void)rampart_publish_signed_event("SIREN_ON", "SIREN_ON", "", nullptr);
    return;
  }

  if (cmd == "SIREN_OFF") {
    Serial0.println("SIREN_OFF: publish event");
    (void)rampart_publish_signed_event("SIREN_OFF", "SIREN_OFF", "", nullptr);
    return;
  }

  Serial0.printf("CMD_UNKNOWN=%s\n", cmd.c_str());
}

static String rampart_sha256_hex(const uint8_t* data, size_t len) {
  uint8_t digest[32];
  if (mbedtls_sha256_ret(data, len, digest, 0) != 0) {
    return String("");
  }

  static const char* HEX_CHARS = "0123456789abcdef";
  char out[65];
  for (int i = 0; i < 32; i++) {
    out[i * 2 + 0] = HEX_CHARS[(digest[i] >> 4) & 0x0F];
    out[i * 2 + 1] = HEX_CHARS[(digest[i] >> 0) & 0x0F];
  }
  out[64] = '\0';
  return String(out);
}

// Phase C crypto block: load/generate ECC keys (NVS: rampart_vault/ecc_priv/ecc_pub),
// sign SHA-256(canonical) using ECDSA P-256, DER signature, base64 transport.
// All cryptographic operations are kept inside this single function.
static bool rampart_sign_canonical_and_get_crypto_block(
  const String& canonical,
  String* out_sig_b64,
  String* out_pubkey_pem,
  String* out_pubkey_fingerprint_hex
) {
  if (!out_sig_b64 || !out_pubkey_pem || !out_pubkey_fingerprint_hex) return false;
  *out_sig_b64 = String("");
  *out_pubkey_pem = String("");
  *out_pubkey_fingerprint_hex = String("");

  // Mandatory verification logging
  Serial0.println("CANONICAL_BACKEND: " + canonical);

  Preferences vault;
  if (!vault.begin("rampart_vault", false)) {
    Serial0.println("SIGN_FAIL (nvs_begin)");
    Serial0.println("SIG_B64: ");
    Serial0.println("PUBKEY_FINGERPRINT: ");
    return false;
  }

  String privPem = vault.getString("ecc_priv", "");
  String pubPemStored = vault.getString("ecc_pub", "");

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_pk_context pk;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_pk_init(&pk);

  const char* pers = "rampart_phaseC";
  int rc = mbedtls_ctr_drbg_seed(
    &ctr_drbg,
    mbedtls_entropy_func,
    &entropy,
    (const unsigned char*)pers,
    strlen(pers)
  );
  if (rc != 0) {
    vault.end();
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    Serial0.println("SIGN_FAIL (ctr_drbg_seed)");
    Serial0.println("SIG_B64: ");
    Serial0.println("PUBKEY_FINGERPRINT: ");
    return false;
  }

  bool needGenerate = privPem.length() == 0;
  if (!needGenerate) {
    // ESP32 Arduino ships an mbedTLS variant where mbedtls_pk_parse_key() does not
    // take RNG parameters.
    rc = mbedtls_pk_parse_key(
      &pk,
      (const unsigned char*)privPem.c_str(),
      privPem.length() + 1,
      nullptr,
      0
    );
    if (rc != 0) {
      needGenerate = true;
    }
  }

  if (needGenerate) {
    Serial0.println("ECC_KEYGEN: generating new ECDSA P-256 keypair");
    mbedtls_pk_free(&pk);
    mbedtls_pk_init(&pk);

    rc = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (rc != 0) {
      vault.end();
      mbedtls_pk_free(&pk);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
      Serial0.println("SIGN_FAIL (pk_setup)");
      Serial0.println("SIG_B64: ");
      Serial0.println("PUBKEY_FINGERPRINT: ");
      return false;
    }

    rc = mbedtls_ecp_gen_key(
      MBEDTLS_ECP_DP_SECP256R1,
      mbedtls_pk_ec(pk),
      mbedtls_ctr_drbg_random,
      &ctr_drbg
    );
    if (rc != 0) {
      vault.end();
      mbedtls_pk_free(&pk);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
      Serial0.println("SIGN_FAIL (ecp_gen_key)");
      Serial0.println("SIG_B64: ");
      Serial0.println("PUBKEY_FINGERPRINT: ");
      return false;
    }

    // PEM encode keys for persistence
    // (size chosen to avoid large stack allocations; P-256 PEM sizes are small)
    const size_t PEM_BUF_SZ = 1024;
    unsigned char* priv_buf = (unsigned char*)malloc(PEM_BUF_SZ);
    unsigned char* pub_buf = (unsigned char*)malloc(PEM_BUF_SZ);
    if (!priv_buf || !pub_buf) {
      if (priv_buf) free(priv_buf);
      if (pub_buf) free(pub_buf);
      vault.end();
      mbedtls_pk_free(&pk);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
      Serial0.println("SIGN_FAIL (malloc_pem)");
      Serial0.println("SIG_B64: ");
      Serial0.println("PUBKEY_FINGERPRINT: ");
      return false;
    }
    memset(priv_buf, 0, PEM_BUF_SZ);
    memset(pub_buf, 0, PEM_BUF_SZ);

    rc = mbedtls_pk_write_key_pem(&pk, priv_buf, PEM_BUF_SZ);
    if (rc != 0) {
      free(priv_buf);
      free(pub_buf);
      vault.end();
      mbedtls_pk_free(&pk);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
      Serial0.println("SIGN_FAIL (write_key_pem)");
      Serial0.println("SIG_B64: ");
      Serial0.println("PUBKEY_FINGERPRINT: ");
      return false;
    }

    rc = mbedtls_pk_write_pubkey_pem(&pk, pub_buf, PEM_BUF_SZ);
    if (rc != 0) {
      free(priv_buf);
      free(pub_buf);
      vault.end();
      mbedtls_pk_free(&pk);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
      Serial0.println("SIGN_FAIL (write_pubkey_pem)");
      Serial0.println("SIG_B64: ");
      Serial0.println("PUBKEY_FINGERPRINT: ");
      return false;
    }

    privPem = String((const char*)priv_buf);
    String pubPem = String((const char*)pub_buf);
    free(priv_buf);
    free(pub_buf);

    // Persist keys (do not wipe if they already exist; only write when generating)
    vault.putString("ecc_priv", privPem);
    vault.putString("ecc_pub", pubPem);
    pubPemStored = pubPem;
  } else {
    // If we loaded a private key successfully but public key is missing/mismatched,
    // re-derive and store public key for consistency.
    const size_t PEM_BUF_SZ = 1024;
    unsigned char* pub_buf = (unsigned char*)malloc(PEM_BUF_SZ);
    if (pub_buf) {
      memset(pub_buf, 0, PEM_BUF_SZ);
      rc = mbedtls_pk_write_pubkey_pem(&pk, pub_buf, PEM_BUF_SZ);
      if (rc == 0) {
        String pubDerived = String((const char*)pub_buf);
        if (pubPemStored.length() == 0 || pubPemStored != pubDerived) {
          vault.putString("ecc_pub", pubDerived);
          pubPemStored = pubDerived;
        }
      }
      free(pub_buf);
    }
  }

  // Compute fingerprint over PEM bytes (matches backend: sha256(pem_utf8))
  *out_pubkey_pem = pubPemStored;
  *out_pubkey_fingerprint_hex = rampart_sha256_hex(
    (const uint8_t*)out_pubkey_pem->c_str(),
    out_pubkey_pem->length()
  );

  // Hash canonical bytes
  uint8_t canon_hash[32];
  rc = mbedtls_sha256_ret(
    (const unsigned char*)canonical.c_str(),
    canonical.length(),
    canon_hash,
    0
  );
  if (rc != 0) {
    vault.end();
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    Serial0.println("SIGN_FAIL (sha256)");
    Serial0.println("SIG_B64: ");
    Serial0.println("PUBKEY_FINGERPRINT: " + *out_pubkey_fingerprint_hex);
    return false;
  }

  // ECDSA signature (DER)
  uint8_t sig_der[80];
  size_t sig_der_len = 0;
  rc = mbedtls_pk_sign(
    &pk,
    MBEDTLS_MD_SHA256,
    canon_hash,
    sizeof(canon_hash),
    sig_der,
    &sig_der_len,
    mbedtls_ctr_drbg_random,
    &ctr_drbg
  );
  if (rc != 0 || sig_der_len == 0) {
    vault.end();
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    Serial0.println("SIGN_FAIL (pk_sign)");
    Serial0.println("SIG_B64: ");
    Serial0.println("PUBKEY_FINGERPRINT: " + *out_pubkey_fingerprint_hex);
    return false;
  }

  // Base64 encode DER signature
  size_t b64_len = 0;
  const size_t B64_MAX = 160;
  unsigned char b64_buf[B64_MAX];
  memset(b64_buf, 0, sizeof(b64_buf));
  rc = mbedtls_base64_encode(b64_buf, sizeof(b64_buf) - 1, &b64_len, sig_der, sig_der_len);
  if (rc != 0 || b64_len == 0) {
    vault.end();
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    Serial0.println("SIGN_FAIL (base64)");
    Serial0.println("SIG_B64: ");
    Serial0.println("PUBKEY_FINGERPRINT: " + *out_pubkey_fingerprint_hex);
    return false;
  }

  *out_sig_b64 = String((const char*)b64_buf);

  // Mandatory verification logging
  Serial0.println("SIG_B64: " + *out_sig_b64);
  Serial0.println("PUBKEY_FINGERPRINT: " + *out_pubkey_fingerprint_hex);
  Serial0.println("SIGN_OK");

  vault.end();
  mbedtls_pk_free(&pk);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return true;
}


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

  mqtt.setCallback(onMqttMessage);

  mqtt.setBufferSize(1024);
  Serial0.println("Connecting to AWS IoT...");
  if (mqtt.connect(CLIENT_ID)) {
    Serial0.println("CONNECTED (GREEN)");
    neopixelWrite(RGB_BUILTIN, 0, 255, 0);

    const bool sub_ok = mqtt.subscribe(g_cmd_topic.c_str());
    if (sub_ok) {
      Serial0.printf("SUB_OK topic=%s\n", g_cmd_topic.c_str());
    } else {
      Serial0.printf("SUB_FAIL topic=%s\n", g_cmd_topic.c_str());
    }
  } else {
    Serial0.printf("FAILED, state=%d", mqtt.state());
    neopixelWrite(RGB_BUILTIN, 255, 0, 0);
  }
}

void setup() {
  Serial0.begin(115200);
  delay(1500);
  Serial0.println("=== RAMPART PHASEC BOOT ===");
  Serial0.printf("RESET_REASON=%d\n", esp_reset_reason());
  Serial0.printf("BUILD: %s %s\n", __DATE__, __TIME__);
  Serial0.printf("FW_VERSION: %s\n", RAMPART_FIRMWARE_VERSION);
  Serial0.printf("BLE_STACK: %s\n", "NimBLE-Arduino");
  Serial0.printf("BLE_NAME: %s\n", DEVICE_ID);
  Serial0.printf("BLE_SERVICE_UUID: %s\n", BlePresence::serviceUuid());
  Serial0.printf("MQTT_TOPIC: %s\n", MQTT_TOPIC);

  g_cmd_topic = rampart_derive_cmd_topic_from_event_topic(MQTT_TOPIC);
  Serial0.printf("CMD_TOPIC: %s\n", g_cmd_topic.c_str());
  Serial0.flush();

  prefs.begin("rampart", false);
  g_device_seq = prefs.getUInt("device_seq", 0);
  g_config_version = prefs.getString("config_version", "");
  Serial0.printf("SEQ_LOADED=%lu\n", (unsigned long)g_device_seq);

  pinMode(TRIGGER_PIN, INPUT);
  neopixelWrite(RGB_BUILTIN, 255, 0, 255); // Boot = Purple

  // BLE presence-driven arming state.
  // Boot default is ARMED until a phone connects.
  g_stateMachine.begin(false);
  g_blePresence.setOwnerPresenceChangedCallback(onOwnerPresenceChanged, &g_stateMachine);
  (void)g_blePresence.begin(DEVICE_ID);

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
  const uint32_t nowMs = (uint32_t)millis();
  if ((uint32_t)(nowMs - lastLog) >= 500u) {
    lastLog = nowMs;
    const int pinNow = digitalRead(TRIGGER_PIN);
    RampartLog::logf(
      "PIN",
      "PIN=%d; ARMED=%d; OWNER_PRESENT=%d; OVERRIDE=%d",
      (pinNow == HIGH) ? 1 : 0,
      rampart_is_armed_effective() ? 1 : 0,
      g_stateMachine.isOwnerPresent() ? 1 : 0
      ,
      g_manual_override ? 1 : 0
    );
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

    if (!rampart_is_armed_effective()) {
      RampartLog::logf("ARM", "motion suppressed (DISARMED)");
      return;
    }

    (void)rampart_publish_signed_event("MOTION_DETECTED", "BREACH_DETECTED", "", nullptr);
  }
}
