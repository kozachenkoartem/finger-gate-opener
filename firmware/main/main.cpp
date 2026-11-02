#include <cstdint>

#include "esp_chip_info.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "led_strip.h"
#include "led_strip_rmt.h"

namespace {

constexpr char kLogTag[] = "board_check";
constexpr int kLedGpio = 8;
constexpr uint32_t kLedCount = 1;
constexpr uint32_t kRmtResolutionHz = 10 * 1000 * 1000;
constexpr TickType_t kColorDelay = pdMS_TO_TICKS(1000);

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
    case CHIP_ESP32C61:
        return "ESP32-C61";
    case CHIP_ESP32C5:
        return "ESP32-C5";
    case CHIP_ESP32H21:
        return "ESP32-H21";
    case CHIP_ESP32H4:
        return "ESP32-H4";
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

led_strip_handle_t initialize_led_strip()
{
    led_strip_config_t strip_config = {};
    strip_config.strip_gpio_num = kLedGpio;
    strip_config.max_leds = kLedCount;
    strip_config.led_model = LED_MODEL_WS2812;
    strip_config.color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB;

    led_strip_rmt_config_t rmt_config = {};
    rmt_config.clk_src = RMT_CLK_SRC_DEFAULT;
    rmt_config.resolution_hz = kRmtResolutionHz;

    led_strip_handle_t led_strip = nullptr;
    ESP_ERROR_CHECK(led_strip_new_rmt_device(&strip_config, &rmt_config, &led_strip));
    ESP_ERROR_CHECK(led_strip_clear(led_strip));
    return led_strip;
}

void show_color(led_strip_handle_t led_strip, uint8_t red, uint8_t green, uint8_t blue)
{
    ESP_ERROR_CHECK(led_strip_set_pixel(led_strip, 0, red, green, blue));
    ESP_ERROR_CHECK(led_strip_refresh(led_strip));
    vTaskDelay(kColorDelay);
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

    const led_strip_handle_t led_strip = initialize_led_strip();
    while (true) {
        show_color(led_strip, 255, 0, 0);
        show_color(led_strip, 0, 255, 0);
        show_color(led_strip, 0, 0, 255);
    }
}
