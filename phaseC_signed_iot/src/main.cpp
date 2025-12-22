#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <time.h>
#include <Preferences.h>

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
#define MQTT_TOPIC    "pts/iot-core/dev/RAMPART-DEV-LIVE/001/event"
#define TRIGGER_PIN   14

WiFiClientSecure net;
PubSubClient mqtt(net);

Preferences prefs;
static uint32_t g_device_seq = 0;


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
    char occurredAtIso[32];
    rampart_iso8601_utc_from_epoch(now_s, occurredAtIso, sizeof(occurredAtIso));

    g_device_seq++;
    prefs.putUInt("device_seq", g_device_seq);
    String event_id = uuidV4();

    // Canonical string for backend verification (exact bytes)
    // Order + keys must match rampart-protocol canonicalizeForSigning().
    String canonical = "{";
    canonical += "\"eventId\":\"" + event_id + "\",";
    canonical += "\"deviceSerial\":\"" DEVICE_ID "\",";
    canonical += "\"backendId\":\"dev\",";
    canonical += "\"eventType\":\"MOTION_DETECTED\",";
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
      return;
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
    payload += "\"event_type\":\"MOTION_DETECTED\",";
    payload += "\"event_time\":" + String(now_s) + ",";
    payload += "\"device_seq\":" + String(g_device_seq) + ",";
    payload += "\"nonce\":\"n-" + String(g_device_seq) + "\",";
    payload += "\"crypto\":{";
    payload += "\"alg\":\"ECDSA_P256_SHA256_DER_B64\",";
    payload += "\"sig\":\"" + sig_b64 + "\",";
    payload += "\"pubkey\":\"" + pubkey_json + "\",";
    payload += "\"pubkey_fingerprint\":\"" + pubkey_fp + "\"},";
    payload += "\"event_id\":\"" + event_id + "\",";
    payload += "\"evidence\":{\"status\":\"BREACH_DETECTED\",\"raw_hash\":\"abababababababababababababababababababababababababababababababab\"}";
    payload += "}";

Serial0.println("Publishing Event...");
 if (mqtt.publish(MQTT_TOPIC, payload.c_str())) {
      Serial0.println("SENT: " + payload);
      neopixelWrite(RGB_BUILTIN, 0, 0, 255); // Blue flash
      delay(200);
      neopixelWrite(RGB_BUILTIN, 0, 255, 0); // Green only after successful signed publish
    } else {
      Serial0.println("PUBLISH_FAIL");
      neopixelWrite(RGB_BUILTIN, 255, 0, 0);
      // NOTE: do not flash GREEN after a failed publish
    }
  }
}
