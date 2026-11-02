#include "driver/gpio.h"
#include "esp_chip_info.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "r558s_driver.hpp"

namespace {

constexpr char kLogTag[] = "board_check";
constexpr int kTouchOutGpio = 3;
constexpr int kLedGpio = 8;
constexpr uart_port_t kR558sUart = UART_NUM_1;
constexpr int kR558sRxGpio = 4;
constexpr int kR558sTxGpio = 5;
constexpr int kR558sBaudRate = 57600;
constexpr int64_t kTouchIndicationDurationUs = 1000000;
constexpr TickType_t kTouchPollDelay = pdMS_TO_TICKS(10);
constexpr TickType_t kBlinkDelay = pdMS_TO_TICKS(1000);

r558s::Driver g_r558s(kR558sUart, kR558sTxGpio, kR558sRxGpio, kR558sBaudRate);

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

void set_r558s_backlight(r558s::LedColor color)
{
    const r558s::TransactionResult result = g_r558s.set_led(color);
    if (result.status != r558s::TransactionStatus::Success) {
        ESP_LOGE(kLogTag, "R558S LED command failed (%d, confirmation 0x%02X)",
                 static_cast<int>(result.status), result.confirmation_code);
    }
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
    g_r558s.initialize();
    set_r558s_backlight(r558s::LedColor::Red);

    gpio_config_t gpio_configuration = {};
    gpio_configuration.pin_bit_mask = 1ULL << kLedGpio;
    gpio_configuration.mode = GPIO_MODE_OUTPUT;
    ESP_ERROR_CHECK(gpio_config(&gpio_configuration));

    bool touch_was_active = gpio_get_level(static_cast<gpio_num_t>(kTouchOutGpio));
    int64_t green_until = 0;
    TickType_t last_blink = xTaskGetTickCount();
    bool led_is_on = false;

    while (true) {
        const bool touch_is_active = gpio_get_level(static_cast<gpio_num_t>(kTouchOutGpio));
        if (touch_is_active && !touch_was_active) {
            ESP_LOGI(kLogTag, "R558S touch detected");
            set_r558s_backlight(r558s::LedColor::Green);
            green_until = esp_timer_get_time() + kTouchIndicationDurationUs;
        }
        touch_was_active = touch_is_active;

        if (green_until != 0 && esp_timer_get_time() >= green_until) {
            set_r558s_backlight(r558s::LedColor::Red);
            green_until = 0;
        }

        const TickType_t now = xTaskGetTickCount();
        if (now - last_blink >= kBlinkDelay) {
            led_is_on = !led_is_on;
            ESP_ERROR_CHECK(gpio_set_level(static_cast<gpio_num_t>(kLedGpio), led_is_on));
            last_blink = now;
        }

        vTaskDelay(kTouchPollDelay);
    }
}
