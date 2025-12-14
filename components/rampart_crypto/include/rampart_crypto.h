#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RAMPART_EVENT_JSON_MAX_LEN 512
#define RAMPART_EVENT_SIGNATURE_MAX_LEN 128
#define RAMPART_CRYPTO_PRIVKEY_MAX_LEN 1024
#define RAMPART_CRYPTO_PUBKEY_MAX_LEN 512

typedef struct {
    char event_id[37];
    char device_serial[32];
    char backend_id[64];
    char event_type[32];
    char occurred_at[25];
    char firmware_version[16];
    char nonce[33];
} rampart_event_payload_t;

typedef struct {
    uint8_t der[RAMPART_EVENT_SIGNATURE_MAX_LEN];
    size_t len;
} rampart_event_signature_t;

esp_err_t rampart_crypto_init(void);
esp_err_t rampart_crypto_get_public_key_pem(char *out_buf, size_t out_buf_size);
esp_err_t rampart_event_build_canonical_json(const rampart_event_payload_t *payload,
                                             char *out_buf,
                                             size_t out_buf_size);
esp_err_t rampart_sign_event(const rampart_event_payload_t *payload,
                             rampart_event_signature_t *out_signature);
esp_err_t rampart_crypto_run_self_test(void);

#ifdef __cplusplus
}
#endif
