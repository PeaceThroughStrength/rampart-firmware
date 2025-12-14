#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "nvs_flash.h"

#include "rampart_ble.h"
#include "rampart_crypto.h"

static const char *TAG = "RAMPART_MAIN";

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    esp_err_t err = rampart_crypto_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "rampart_crypto_init failed: %s", esp_err_to_name(err));
    } else {
        ESP_LOGI(TAG, "Rampart crypto module initialized");
        // Self-test disabled by default to avoid stack overflow on the main task.
        // To re-enable, call rampart_crypto_run_self_test() from a dedicated test task with a larger stack.
        // rampart_crypto_run_self_test();
    }

    ESP_LOGI(TAG, "Starting Rampart BLE stack");
    ESP_ERROR_CHECK(rampart_ble_init());

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
