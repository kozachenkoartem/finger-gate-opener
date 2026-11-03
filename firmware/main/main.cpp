#include "driver/gpio.h"
#include "esp_chip_info.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "fingerprint_task.hpp"
#include "provisioning.hpp"
#include "nvs_storage.hpp"
#include "http_server.hpp"

namespace {

constexpr char kLogTag[] = "board_check";
constexpr int kTouchOutGpio = 3;

const char* chip_model_name(esp_chip_model_t model)
{
    switch (model) {
    case CHIP_ESP32C3:
        return "ESP32-C3";
    case CHIP_ESP32:
        return "ESP32";
    case CHIP_ESP32S2:
        return "ESP32-S2";
    case CHIP_ESP32S3:
        return "ESP32-S3";
    case CHIP_ESP32C2:
        return "ESP32-C2";
    case CHIP_ESP32C6:
        return "ESP32-C6";
    case CHIP_ESP32H2:
        return "ESP32-H2";
    case CHIP_ESP32P4:
        return "ESP32-P4";
    case CHIP_POSIX_LINUX:
        return "POSIX/Linux";
    default:
        return "unknown";
    }
}

const char* reset_reason_name(esp_reset_reason_t reason)
{
    switch (reason) {
    case ESP_RST_POWERON:
        return "power-on";
    case ESP_RST_EXT:
        return "external pin";
    case ESP_RST_SW:
        return "software";
    case ESP_RST_PANIC:
        return "panic";
    case ESP_RST_INT_WDT:
        return "interrupt watchdog";
    case ESP_RST_TASK_WDT:
        return "task watchdog";
    case ESP_RST_WDT:
        return "watchdog";
    case ESP_RST_DEEPSLEEP:
        return "deep sleep";
    case ESP_RST_BROWNOUT:
        return "brownout";
    case ESP_RST_SDIO:
        return "SDIO";
    case ESP_RST_USB:
        return "USB";
    case ESP_RST_JTAG:
        return "JTAG";
    case ESP_RST_EFUSE:
        return "eFuse";
    case ESP_RST_PWR_GLITCH:
        return "power glitch";
    case ESP_RST_CPU_LOCKUP:
        return "CPU lockup";
    case ESP_RST_UNKNOWN:
    default:
        return "unknown";
    }
}

void configure_touch_out()
{
    gpio_config_t configuration = {};
    configuration.pin_bit_mask = 1ULL << kTouchOutGpio;
    configuration.mode = GPIO_MODE_INPUT;
    configuration.pull_down_en = GPIO_PULLDOWN_DISABLE;
    configuration.pull_up_en = GPIO_PULLUP_DISABLE;
    ESP_ERROR_CHECK(gpio_config(&configuration));
}

}

extern "C" void app_main()
{
    esp_chip_info_t chip_info = {};
    esp_chip_info(&chip_info);
    const esp_reset_reason_t reset_reason = esp_reset_reason();

    ESP_LOGI(kLogTag, "Chip: %s (model %d, revision %u, %u core(s))",
             chip_model_name(chip_info.model), chip_info.model, chip_info.revision, chip_info.cores);
    ESP_LOGI(kLogTag, "ESP-IDF: %s", esp_get_idf_version());
    ESP_LOGI(kLogTag, "Last reset: %s (%d)", reset_reason_name(reset_reason), reset_reason);
    ESP_LOGI(kLogTag, "Free heap: %lu bytes", static_cast<unsigned long>(esp_get_free_heap_size()));

    configure_touch_out();
    static fg::NvsKeyValueStore storage;
    if (storage.initialize() != fg::StoreResult::Ok) {
        ESP_LOGE(kLogTag, "NVS initialization failed; provisioning is disabled");
        return;
    }
    static fg::FingerprintTask fingerprint_task(storage);
    fingerprint_task.start();
    static fg::Provisioning provisioning(storage, fingerprint_task);
    const esp_err_t network_result = provisioning.start();
    if (network_result == ESP_OK) {
        static fg::AdminServer admin(storage, provisioning, fingerprint_task);
        admin.start();
    } else {
        ESP_LOGE(kLogTag, "Networking unavailable: %s", esp_err_to_name(network_result));
    }

    while (true) {
        if (network_result == ESP_OK) provisioning.poll();
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}
