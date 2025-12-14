#include <string.h>

#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_gatt_common_api.h"
#include "esp_gatts_api.h"
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "rampart_ble.h"

#define DEVICE_NAME "Rampart-Dev"
#define RAMPART_APP_ID 0
#define SVC_INST_ID 0

#define RAMPART_SERVICE_UUID      0xA001
#define RAMPART_SERIAL_UUID       0xA002
#define RAMPART_FIRMWARE_UUID     0xA003
#define RAMPART_OWNER_KEY_UUID    0xA004
#define RAMPART_ARM_STATE_UUID    0xA005
#define RAMPART_SIREN_UUID        0xA006
#define RAMPART_HEARTBEAT_UUID    0xA007

#define ADV_CONFIG_FLAG    (1 << 0)

#define OWNER_KEY_MAX_LEN      64
#define SERIAL_NUMBER_DEFAULT  "RAMPART-SERIAL-0001"
#define FIRMWARE_VERSION       "0.0.1"

static const char *TAG = "RAMPART_BLE";

enum {
    IDX_SVC,
    IDX_CHAR_SERIAL,
    IDX_CHAR_VAL_SERIAL,
    IDX_CHAR_FW,
    IDX_CHAR_VAL_FW,
    IDX_CHAR_OWNER,
    IDX_CHAR_VAL_OWNER,
    IDX_CHAR_ARM,
    IDX_CHAR_VAL_ARM,
    IDX_CHAR_SIREN,
    IDX_CHAR_VAL_SIREN,
    IDX_CHAR_HEARTBEAT,
    IDX_CHAR_VAL_HEARTBEAT,
    IDX_CHAR_CFG_HEARTBEAT,
    IDX_NB,
};

static uint8_t adv_config_done;

static uint8_t serial_number_value[] = SERIAL_NUMBER_DEFAULT;
static uint8_t firmware_version_value[] = FIRMWARE_VERSION;
static char s_owner_key[OWNER_KEY_MAX_LEN + 1];
static uint8_t arm_state_value = 0x00;
static uint8_t siren_command_value = 0x00;
static uint8_t heartbeat_value[8] = {0};
static uint8_t heartbeat_ccc[2] = {0x00, 0x00};

static const uint16_t primary_service_uuid = ESP_GATT_UUID_PRI_SERVICE;
static const uint16_t character_decl_uuid = ESP_GATT_UUID_CHAR_DECLARE;
static const uint16_t client_char_cfg_uuid = ESP_GATT_UUID_CHAR_CLIENT_CONFIG;

static const uint8_t char_prop_read = ESP_GATT_CHAR_PROP_BIT_READ;
static const uint8_t char_prop_read_write = ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_WRITE;
static const uint8_t char_prop_write = ESP_GATT_CHAR_PROP_BIT_WRITE;
static const uint8_t char_prop_notify = ESP_GATT_CHAR_PROP_BIT_NOTIFY;

static const uint16_t rampart_service_uuid = RAMPART_SERVICE_UUID;
static const uint16_t rampart_serial_uuid = RAMPART_SERIAL_UUID;
static const uint16_t rampart_firmware_uuid = RAMPART_FIRMWARE_UUID;
static const uint16_t rampart_owner_uuid = RAMPART_OWNER_KEY_UUID;
static const uint16_t rampart_arm_uuid = RAMPART_ARM_STATE_UUID;
static const uint16_t rampart_siren_uuid = RAMPART_SIREN_UUID;
static const uint16_t rampart_heartbeat_uuid = RAMPART_HEARTBEAT_UUID;

static const esp_ble_adv_params_t rampart_adv_params = {
    .adv_int_min = 0x20,
    .adv_int_max = 0x40,
    .adv_type = ADV_TYPE_IND,
    .own_addr_type = BLE_ADDR_TYPE_PUBLIC,
    .channel_map = ADV_CHNL_ALL,
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

static uint8_t rampart_service_uuid128[16] = {
    // LSB -----------------------------------------------------------------> MSB
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
    0x00, 0x10, 0x00, 0x00, 0x01, 0xa0, 0x00, 0x00,
};

static esp_ble_adv_data_t rampart_adv_data = {
    .set_scan_rsp = false,
    .include_name = true,
    .include_txpower = false,
    .min_interval = 0x20,
    .max_interval = 0x40,
    .appearance = 0x00,
    .manufacturer_len = 0,
    .p_manufacturer_data = NULL,
    .service_data_len = 0,
    .p_service_data = NULL,
    .service_uuid_len = sizeof(rampart_service_uuid128),
    .p_service_uuid = rampart_service_uuid128,
    .flag = (ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT),
};

static void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param);
static void rampart_owner_key_init_from_nvs(void);
static esp_err_t rampart_owner_key_save_to_nvs(const char *owner_key);
static void rampart_owner_key_sync_attr_value(void);
static esp_err_t rampart_handle_write_event(esp_ble_gatts_cb_param_t *param);

static struct {
    esp_gatt_if_t gatts_if;
    uint16_t conn_id;
    uint16_t handle_table[IDX_NB];
} s_rampart_profile = {
    .gatts_if = ESP_GATT_IF_NONE,
    .conn_id = 0xFFFF,
};

static const esp_gatts_attr_db_t rampart_gatt_db[IDX_NB] = {
    [IDX_SVC] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&primary_service_uuid, ESP_GATT_PERM_READ,
                  sizeof(uint16_t), sizeof(rampart_service_uuid), (uint8_t *)&rampart_service_uuid}},

    [IDX_CHAR_SERIAL] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_decl_uuid, ESP_GATT_PERM_READ,
                      sizeof(uint8_t), sizeof(uint8_t), (uint8_t *)&char_prop_read}},
    [IDX_CHAR_VAL_SERIAL] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&rampart_serial_uuid, ESP_GATT_PERM_READ,
                         sizeof(serial_number_value) - 1, sizeof(serial_number_value) - 1, serial_number_value}},

    [IDX_CHAR_FW] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_decl_uuid, ESP_GATT_PERM_READ,
                  sizeof(uint8_t), sizeof(uint8_t), (uint8_t *)&char_prop_read}},
    [IDX_CHAR_VAL_FW] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&rampart_firmware_uuid, ESP_GATT_PERM_READ,
                       sizeof(firmware_version_value) - 1, sizeof(firmware_version_value) - 1, firmware_version_value}},

    [IDX_CHAR_OWNER] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_decl_uuid, ESP_GATT_PERM_READ,
                    sizeof(uint8_t), sizeof(uint8_t), (uint8_t *)&char_prop_read_write}},
    [IDX_CHAR_VAL_OWNER] = {{ESP_GATT_RSP_BY_APP}, {ESP_UUID_LEN_16, (uint8_t *)&rampart_owner_uuid, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
                        OWNER_KEY_MAX_LEN, 0, (uint8_t *)s_owner_key}},

    [IDX_CHAR_ARM] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_decl_uuid, ESP_GATT_PERM_READ,
                  sizeof(uint8_t), sizeof(uint8_t), (uint8_t *)&char_prop_read_write}},
    [IDX_CHAR_VAL_ARM] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&rampart_arm_uuid, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
                       sizeof(arm_state_value), sizeof(arm_state_value), &arm_state_value}},

    [IDX_CHAR_SIREN] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_decl_uuid, ESP_GATT_PERM_READ,
                    sizeof(uint8_t), sizeof(uint8_t), (uint8_t *)&char_prop_write}},
    [IDX_CHAR_VAL_SIREN] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&rampart_siren_uuid, ESP_GATT_PERM_WRITE,
                        sizeof(siren_command_value), sizeof(siren_command_value), &siren_command_value}},

    [IDX_CHAR_HEARTBEAT] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_decl_uuid, ESP_GATT_PERM_READ,
                        sizeof(uint8_t), sizeof(uint8_t), (uint8_t *)&char_prop_notify}},
    [IDX_CHAR_VAL_HEARTBEAT] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&rampart_heartbeat_uuid, ESP_GATT_PERM_READ,
                             sizeof(heartbeat_value), sizeof(heartbeat_value), heartbeat_value}},
    [IDX_CHAR_CFG_HEARTBEAT] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&client_char_cfg_uuid, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
                              sizeof(uint16_t), sizeof(heartbeat_ccc), heartbeat_ccc}},
};

static void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param)
{
    switch (event) {
        case ESP_GAP_BLE_ADV_DATA_SET_COMPLETE_EVT:
            adv_config_done &= ~ADV_CONFIG_FLAG;
            if (adv_config_done == 0) {
                esp_ble_gap_start_advertising((esp_ble_adv_params_t *)&rampart_adv_params);
            }
            break;
        case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
            if (param->adv_start_cmpl.status != ESP_BT_STATUS_SUCCESS) {
                ESP_LOGE(TAG, "Failed to start advertising: %s", esp_err_to_name(param->adv_start_cmpl.status));
            } else {
                ESP_LOGI(TAG, "Advertising as %s", DEVICE_NAME);
            }
            break;
        case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
            ESP_LOGI(TAG, "Advertising stopped");
            break;
        default:
            break;
    }
}

static void rampart_log_write_payload(const char *label, const uint8_t *data, uint16_t len)
{
    char buffer[64];
    size_t log_len = len < (sizeof(buffer) - 1) ? len : (sizeof(buffer) - 1);
    memcpy(buffer, data, log_len);
    buffer[log_len] = '\0';
    ESP_LOGI(TAG, "%s write (%u bytes): %s", label, len, buffer);
}

static void rampart_owner_key_init_from_nvs(void)
{
    s_owner_key[0] = '\0';

    nvs_handle_t handle;
    esp_err_t err = nvs_open("rampart", NVS_READONLY, &handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to open NVS for OWNER_KEY read: %s", esp_err_to_name(err));
        return;
    }

    size_t required_size = sizeof(s_owner_key);
    err = nvs_get_str(handle, "owner_key", s_owner_key, &required_size);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGI(TAG, "No OWNER_KEY stored in NVS; defaulting to empty string");
        s_owner_key[0] = '\0';
    } else if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to read OWNER_KEY from NVS: %s", esp_err_to_name(err));
        s_owner_key[0] = '\0';
    } else {
        ESP_LOGI(TAG, "Loaded OWNER_KEY (%zu bytes) from NVS", strnlen(s_owner_key, OWNER_KEY_MAX_LEN));
    }

    nvs_close(handle);
}

static esp_err_t rampart_owner_key_save_to_nvs(const char *owner_key)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open("rampart", NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to open NVS for OWNER_KEY write: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs_set_str(handle, "owner_key", owner_key);
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to persist OWNER_KEY: %s", esp_err_to_name(err));
    }

    nvs_close(handle);
    return err;
}

static void rampart_owner_key_sync_attr_value(void)
{
    if (s_rampart_profile.handle_table[IDX_CHAR_VAL_OWNER] == 0) {
        return;
    }

    const uint16_t owner_key_len = (uint16_t)strnlen(s_owner_key, OWNER_KEY_MAX_LEN);
    esp_err_t err = esp_ble_gatts_set_attr_value(
        s_rampart_profile.handle_table[IDX_CHAR_VAL_OWNER],
        owner_key_len,
        (uint8_t *)s_owner_key);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to sync OWNER_KEY attribute value: %s", esp_err_to_name(err));
    }
}

static esp_err_t rampart_handle_write_event(esp_ble_gatts_cb_param_t *param)
{
    const uint16_t handle = param->write.handle;

    if (handle == s_rampart_profile.handle_table[IDX_CHAR_VAL_OWNER]) {
        size_t copy_len = param->write.len;
        if (copy_len > OWNER_KEY_MAX_LEN) {
            copy_len = OWNER_KEY_MAX_LEN;
        }

        memcpy(s_owner_key, param->write.value, copy_len);
        s_owner_key[copy_len] = '\0';
        rampart_log_write_payload("OWNER_KEY", (const uint8_t *)s_owner_key, (uint16_t)copy_len);

        rampart_owner_key_sync_attr_value();

        esp_err_t save_err = rampart_owner_key_save_to_nvs(s_owner_key);
        if (save_err == ESP_OK) {
            ESP_LOGI(TAG, "OWNER_KEY persisted (%zu bytes)", strnlen(s_owner_key, OWNER_KEY_MAX_LEN));
        } else {
            ESP_LOGW(TAG, "Failed to persist OWNER_KEY: %s", esp_err_to_name(save_err));
        }

        return save_err;
    }

    if (handle == s_rampart_profile.handle_table[IDX_CHAR_VAL_ARM]) {
        if (param->write.len > 0) {
            arm_state_value = param->write.value[0];
            esp_ble_gatts_set_attr_value(handle, sizeof(arm_state_value), &arm_state_value);
            ESP_LOGI(TAG, "ARM_STATE set to 0x%02X", arm_state_value);
            // TODO: Apply arm/disarm state machine transitions here.
        }
        return ESP_OK;
    }

    if (handle == s_rampart_profile.handle_table[IDX_CHAR_VAL_SIREN]) {
        if (param->write.len > 0) {
            siren_command_value = param->write.value[0];
            ESP_LOGI(TAG, "SIREN_COMMAND received: 0x%02X", siren_command_value);
            // TODO: Trigger siren actuator once real hardware control is implemented.
        }
        return ESP_OK;
    }

    return ESP_OK;
}

static void gatts_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if,
                                esp_ble_gatts_cb_param_t *param)
{
    switch (event) {
        case ESP_GATTS_REG_EVT:
            ESP_LOGI(TAG, "GATT registration status=%d, app_id=%d", param->reg.status, param->reg.app_id);
            if (param->reg.status != ESP_GATT_OK) {
                ESP_LOGE(TAG, "GATT registration failed: %s", esp_err_to_name(param->reg.status));
                return;
            }
            s_rampart_profile.gatts_if = gatts_if;
            esp_ble_gap_set_device_name(DEVICE_NAME);
            adv_config_done |= ADV_CONFIG_FLAG;
            esp_ble_gap_config_adv_data(&rampart_adv_data);
            esp_ble_gatts_create_attr_tab(rampart_gatt_db, gatts_if, IDX_NB, SVC_INST_ID);
            esp_ble_gatt_set_local_mtu(500);
            break;
        case ESP_GATTS_CREAT_ATTR_TAB_EVT:
            if (param->add_attr_tab.status != ESP_GATT_OK) {
                ESP_LOGE(TAG, "Failed to create attribute table, error %d", param->add_attr_tab.status);
                break;
            }
            memcpy(s_rampart_profile.handle_table, param->add_attr_tab.handles, sizeof(uint16_t) * IDX_NB);
            rampart_owner_key_sync_attr_value();
            esp_ble_gatts_start_service(s_rampart_profile.handle_table[IDX_SVC]);
            ESP_LOGI(TAG, "Rampart service started");
            break;
        case ESP_GATTS_READ_EVT:
            if (param->read.handle == s_rampart_profile.handle_table[IDX_CHAR_VAL_OWNER] && param->read.need_rsp) {
                esp_gatt_rsp_t rsp = {0};
                rsp.attr_value.handle = param->read.handle;
                const uint16_t owner_key_len = (uint16_t)strnlen(s_owner_key, OWNER_KEY_MAX_LEN);
                rsp.attr_value.len = owner_key_len;
                memcpy(rsp.attr_value.value, s_owner_key, owner_key_len);
                rsp.attr_value.auth_req = ESP_GATT_AUTH_REQ_NONE;

                esp_err_t rsp_err = esp_ble_gatts_send_response(gatts_if, param->read.conn_id, param->read.trans_id, ESP_GATT_OK, &rsp);
                if (rsp_err != ESP_OK) {
                    ESP_LOGW(TAG, "Failed to send OWNER_KEY read response: %s", esp_err_to_name(rsp_err));
                } else {
                    ESP_LOGI(TAG, "OWNER_KEY read responded (%u bytes)", owner_key_len);
                }
            }
            break;
        case ESP_GATTS_START_EVT:
            ESP_LOGI(TAG, "Service start event status=%d", param->start.status);
            break;
        case ESP_GATTS_CONNECT_EVT:
            s_rampart_profile.conn_id = param->connect.conn_id;
            ESP_LOGI(TAG, "Device connected, conn_id=%u", s_rampart_profile.conn_id);
            break;
        case ESP_GATTS_DISCONNECT_EVT:
            ESP_LOGI(TAG, "Device disconnected, restarting advertising");
            s_rampart_profile.conn_id = 0xFFFF;
            esp_ble_gap_start_advertising((esp_ble_adv_params_t *)&rampart_adv_params);
            break;
        case ESP_GATTS_WRITE_EVT:
            if (!param->write.is_prep) {
                esp_err_t write_status = rampart_handle_write_event(param);
                if (param->write.handle == s_rampart_profile.handle_table[IDX_CHAR_VAL_OWNER] && param->write.need_rsp) {
                    esp_gatt_rsp_t rsp = {0};
                    rsp.attr_value.handle = param->write.handle;
                    rsp.attr_value.len = 0;
                    rsp.attr_value.auth_req = ESP_GATT_AUTH_REQ_NONE;

                    const esp_gatt_status_t gatt_status = (write_status == ESP_OK) ? ESP_GATT_OK : ESP_GATT_INTERNAL_ERROR;
                    esp_err_t rsp_err = esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, gatt_status, &rsp);
                    if (rsp_err != ESP_OK) {
                        ESP_LOGW(TAG, "Failed to send OWNER_KEY write response: %s", esp_err_to_name(rsp_err));
                    }
                }
            }
            break;
        default:
            break;
    }
}

esp_err_t rampart_ble_init(void)
{
    esp_err_t ret = esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "Failed to release classic BT memory: %s", esp_err_to_name(ret));
        return ret;
    }

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();

    ret = esp_bt_controller_init(&bt_cfg);
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "BT controller init failed: %s", esp_err_to_name(ret));
        return ret;
    }

    ret = esp_bt_controller_enable(ESP_BT_MODE_BLE);
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "BT controller enable failed: %s", esp_err_to_name(ret));
        return ret;
    }

    ret = esp_bluedroid_init();
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "Bluedroid init failed: %s", esp_err_to_name(ret));
        return ret;
    }

    ret = esp_bluedroid_enable();
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "Bluedroid enable failed: %s", esp_err_to_name(ret));
        return ret;
    }

    rampart_owner_key_init_from_nvs();

    ret = esp_ble_gatts_register_callback(gatts_event_handler);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register GATTS callback: %s", esp_err_to_name(ret));
        return ret;
    }

    ret = esp_ble_gap_register_callback(gap_event_handler);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register GAP callback: %s", esp_err_to_name(ret));
        return ret;
    }

    ret = esp_ble_gatts_app_register(RAMPART_APP_ID);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "GATTS app register failed: %s", esp_err_to_name(ret));
        return ret;
    }

    ESP_LOGI(TAG, "Rampart BLE initialized");
    return ESP_OK;
}
