#include "rampart_crypto.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"

#define TAG "RAMPART_CRYPTO"

#define NVS_NAMESPACE "rampart"
#define NVS_KEY_PRIV "ecdsa_priv_pem"
#define NVS_KEY_PUB  "ecdsa_pub_pem"

static mbedtls_pk_context s_device_key;
static mbedtls_entropy_context s_entropy;
static mbedtls_ctr_drbg_context s_ctr_drbg;
static bool s_crypto_ready = false;
static char s_priv_pem[RAMPART_CRYPTO_PRIVKEY_MAX_LEN];
static char s_pub_pem[RAMPART_CRYPTO_PUBKEY_MAX_LEN];

static void rampart_crypto_cleanup(void)
{
    mbedtls_pk_free(&s_device_key);
    mbedtls_ctr_drbg_free(&s_ctr_drbg);
    mbedtls_entropy_free(&s_entropy);
    memset(s_priv_pem, 0, sizeof(s_priv_pem));
    memset(s_pub_pem, 0, sizeof(s_pub_pem));
    s_crypto_ready = false;
}

static void rampart_crypto_reset_pk_context(void)
{
    mbedtls_pk_free(&s_device_key);
    mbedtls_pk_init(&s_device_key);
}

static void rampart_crypto_log_mbedtls_error(const char *message, int err)
{
    char err_buf[64];
    mbedtls_strerror(err, err_buf, sizeof(err_buf));
    ESP_LOGE(TAG, "%s (0x%04X): %s", message, (unsigned)(-err), err_buf);
}

static esp_err_t rampart_crypto_load_keys_from_nvs(nvs_handle_t handle, bool *out_loaded)
{
    if (!out_loaded) {
        return ESP_ERR_INVALID_ARG;
    }

    *out_loaded = false;

    size_t priv_len = sizeof(s_priv_pem);
    esp_err_t err = nvs_get_str(handle, NVS_KEY_PRIV, s_priv_pem, &priv_len);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_OK;
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read private key from NVS (%s)", esp_err_to_name(err));
        return err;
    }

    size_t pub_len = sizeof(s_pub_pem);
    err = nvs_get_str(handle, NVS_KEY_PUB, s_pub_pem, &pub_len);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        s_priv_pem[0] = '\0';
        return ESP_OK;
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read public key from NVS (%s)", esp_err_to_name(err));
        s_priv_pem[0] = '\0';
        return err;
    }

    rampart_crypto_reset_pk_context();

    int ret = mbedtls_pk_parse_key(&s_device_key,
                                   (const unsigned char *)s_priv_pem,
                                   priv_len,
                                   NULL,
                                   0,
                                   NULL,
                                   NULL);
    if (ret != 0) {
        rampart_crypto_log_mbedtls_error("Failed to parse stored private key", ret);
        s_priv_pem[0] = '\0';
        s_pub_pem[0] = '\0';
        return ESP_OK;
    }

    *out_loaded = true;
    return ESP_OK;
}

static esp_err_t rampart_crypto_generate_and_store_keys(nvs_handle_t handle)
{
    rampart_crypto_reset_pk_context();

    const mbedtls_pk_info_t *pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
    if (pk_info == NULL) {
        ESP_LOGE(TAG, "Failed to get PK info for ECKEY");
        return ESP_FAIL;
    }

    int ret = mbedtls_pk_setup(&s_device_key, pk_info);
    if (ret != 0) {
        rampart_crypto_log_mbedtls_error("mbedtls_pk_setup failed", ret);
        return ESP_FAIL;
    }

    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                              mbedtls_pk_ec(s_device_key),
                              mbedtls_ctr_drbg_random,
                              &s_ctr_drbg);
    if (ret != 0) {
        rampart_crypto_log_mbedtls_error("Failed to generate secp256r1 key", ret);
        return ESP_FAIL;
    }

    ret = mbedtls_pk_write_key_pem(&s_device_key, (unsigned char *)s_priv_pem, sizeof(s_priv_pem));
    if (ret != 0) {
        rampart_crypto_log_mbedtls_error("Failed to export private key PEM", ret);
        return ESP_FAIL;
    }

    ret = mbedtls_pk_write_pubkey_pem(&s_device_key, (unsigned char *)s_pub_pem, sizeof(s_pub_pem));
    if (ret != 0) {
        rampart_crypto_log_mbedtls_error("Failed to export public key PEM", ret);
        return ESP_FAIL;
    }

    esp_err_t err = nvs_set_str(handle, NVS_KEY_PRIV, s_priv_pem);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to persist private key PEM (%s)", esp_err_to_name(err));
        return err;
    }

    err = nvs_set_str(handle, NVS_KEY_PUB, s_pub_pem);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to persist public key PEM (%s)", esp_err_to_name(err));
        return err;
    }

    err = nvs_commit(handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit NVS key material (%s)", esp_err_to_name(err));
        return err;
    }

    return ESP_OK;
}

esp_err_t rampart_crypto_init(void)
{
    ESP_LOGI(TAG, "Initializing Rampart crypto module");

    if (s_crypto_ready) {
        return ESP_OK;
    }

    esp_err_t err = ESP_OK;
    int ret;

    mbedtls_pk_init(&s_device_key);
    mbedtls_entropy_init(&s_entropy);
    mbedtls_ctr_drbg_init(&s_ctr_drbg);

    const unsigned char personalization[] = "rampart-crypto";
    ret = mbedtls_ctr_drbg_seed(&s_ctr_drbg,
                                mbedtls_entropy_func,
                                &s_entropy,
                                personalization,
                                sizeof(personalization) - 1);
    if (ret != 0) {
        rampart_crypto_log_mbedtls_error("Failed to seed CTR_DRBG", ret);
        rampart_crypto_cleanup();
        return ESP_FAIL;
    }

    nvs_handle_t nvs_handle = 0;
    bool nvs_opened = false;
    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS namespace '%s' (%s)", NVS_NAMESPACE, esp_err_to_name(err));
        rampart_crypto_cleanup();
        return err;
    }
    nvs_opened = true;

    bool keys_loaded = false;
    err = rampart_crypto_load_keys_from_nvs(nvs_handle, &keys_loaded);
    if (err != ESP_OK) {
        if (nvs_opened) {
            nvs_close(nvs_handle);
            nvs_opened = false;
        }
        rampart_crypto_cleanup();
        return err;
    }

    if (!keys_loaded) {
        err = rampart_crypto_generate_and_store_keys(nvs_handle);
        if (err != ESP_OK) {
            if (nvs_opened) {
                nvs_close(nvs_handle);
                nvs_opened = false;
            }
            rampart_crypto_cleanup();
            return err;
        }
        ESP_LOGI(TAG, "Generated new ECDSA P-256 keypair");
    } else {
        ESP_LOGI(TAG, "Loaded existing ECDSA P-256 keypair from NVS");
    }

    if (nvs_opened) {
        nvs_close(nvs_handle);
        nvs_opened = false;
    }

    s_crypto_ready = true;
    return ESP_OK;
}

esp_err_t rampart_crypto_get_public_key_pem(char *out_buf, size_t out_buf_size)
{
    if (!s_crypto_ready) {
        return ESP_ERR_INVALID_STATE;
    }

    if (out_buf == NULL || out_buf_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t pub_len = strnlen(s_pub_pem, sizeof(s_pub_pem)) + 1;
    if (pub_len > out_buf_size) {
        return ESP_ERR_INVALID_SIZE;
    }

    memcpy(out_buf, s_pub_pem, pub_len);
    return ESP_OK;
}

esp_err_t rampart_event_build_canonical_json(const rampart_event_payload_t *payload,
                                             char *out_buf,
                                             size_t out_buf_size)
{
    if (payload == NULL || out_buf == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    int written = snprintf(out_buf,
                           out_buf_size,
                           "{\"eventId\":\"%s\",\"deviceSerial\":\"%s\",\"backendId\":\"%s\","
                           "\"eventType\":\"%s\",\"occurredAt\":\"%s\",\"firmwareVersion\":\"%s\",\"nonce\":\"%s\"}",
                           payload->event_id,
                           payload->device_serial,
                           payload->backend_id,
                           payload->event_type,
                           payload->occurred_at,
                           payload->firmware_version,
                           payload->nonce);

    if (written < 0) {
        return ESP_FAIL;
    }

    if ((size_t)written >= out_buf_size) {
        return ESP_ERR_INVALID_SIZE;
    }

    ESP_LOGI(TAG, "Built canonical event JSON (%d bytes)", written);
    return ESP_OK;
}

esp_err_t rampart_sign_event(const rampart_event_payload_t *payload,
                             rampart_event_signature_t *out_signature)
{
    if (!s_crypto_ready) {
        return ESP_ERR_INVALID_STATE;
    }

    if (payload == NULL || out_signature == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    out_signature->len = 0;

    char json[RAMPART_EVENT_JSON_MAX_LEN];
    esp_err_t err = rampart_event_build_canonical_json(payload, json, sizeof(json));
    if (err != ESP_OK) {
        return err;
    }

    unsigned char hash[32];
    int ret = mbedtls_sha256((const unsigned char *)json, strlen(json), hash, 0);
    if (ret != 0) {
        rampart_crypto_log_mbedtls_error("Failed to hash canonical payload", ret);
        return ESP_FAIL;
    }

    size_t sig_len = 0;
    ret = mbedtls_pk_sign(&s_device_key,
                          MBEDTLS_MD_SHA256,
                          hash,
                          sizeof(hash),
                          out_signature->der,
                          sizeof(out_signature->der),
                          &sig_len,
                          mbedtls_ctr_drbg_random,
                          &s_ctr_drbg);
    if (ret != 0) {
        rampart_crypto_log_mbedtls_error("Failed to sign payload", ret);
        return ESP_FAIL;
    }

    out_signature->len = sig_len;
    ESP_LOGI(TAG, "Signed event with ECDSA P-256, signature length=%u", (unsigned)out_signature->len);
    return ESP_OK;
}

static void rampart_crypto_hex_encode(const uint8_t *data, size_t len, char *out, size_t out_size)
{
    if (out == NULL || out_size == 0) {
        return;
    }

    size_t required = len * 2 + 1;
    if (out_size < required) {
        out[0] = '\0';
        return;
    }

    for (size_t i = 0; i < len; ++i) {
        snprintf(out + (i * 2), out_size - (i * 2), "%02X", data[i]);
    }
    out[len * 2] = '\0';
}

esp_err_t rampart_crypto_run_self_test(void)
{
    if (!s_crypto_ready) {
        return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(TAG, "Running Rampart crypto self-test (ECDSA P-256)");

    rampart_event_payload_t dummy = {
        .event_id = "00000000-0000-0000-0000-000000000000",
        .device_serial = "RAMPART-SERIAL-0001",
        .backend_id = "dev_dummy",
        .event_type = "INTRUSION_TEST",
        .occurred_at = "2025-01-01T00:00:00.000Z",
        .firmware_version = "0.0.1",
        .nonce = "0123456789abcdef0123456789abcdef"
    };

    char json[RAMPART_EVENT_JSON_MAX_LEN];
    esp_err_t err = rampart_event_build_canonical_json(&dummy, json, sizeof(json));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Self-test JSON build failed (%s)", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "Self-test canonical JSON: %s", json);

    rampart_event_signature_t signature = {0};
    err = rampart_sign_event(&dummy, &signature);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Self-test signing failed (%s)", esp_err_to_name(err));
        return err;
    }

    char signature_hex[RAMPART_EVENT_SIGNATURE_MAX_LEN * 2 + 1];
    rampart_crypto_hex_encode(signature.der, signature.len, signature_hex, sizeof(signature_hex));

    ESP_LOGI(TAG, "Event signature (DER hex, %u bytes): %s", (unsigned)signature.len, signature_hex);

    char pubkey_pem[512];
    err = rampart_crypto_get_public_key_pem(pubkey_pem, sizeof(pubkey_pem));
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Public key PEM:\n%s", pubkey_pem);
    } else {
        ESP_LOGE(TAG, "Failed to fetch public key PEM for self-test (%s)", esp_err_to_name(err));
    }

    return ESP_OK;
}
