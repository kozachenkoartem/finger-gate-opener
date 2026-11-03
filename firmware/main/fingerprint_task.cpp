#include "fingerprint_task.hpp"

#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/task.h"

namespace fg {
namespace {

constexpr char kLogTag[] = "fingerprint";
constexpr int kTouchOutGpio = 3;
constexpr TickType_t kPollDelay = pdMS_TO_TICKS(10);

r558s::LedColor led_color(IndicatorColor color)
{
    switch (color) {
    case IndicatorColor::Off: return r558s::LedColor::Off;
    case IndicatorColor::Blue: return r558s::LedColor::Blue;
    case IndicatorColor::Green: return r558s::LedColor::Green;
    case IndicatorColor::Red: return r558s::LedColor::Red;
    case IndicatorColor::Yellow: return r558s::LedColor::Yellow;
    }
    return r558s::LedColor::Off;
}

void log_database(r558s::Driver& driver)
{
    const r558s::TransactionResult count = driver.template_count();
    if (count.status != r558s::TransactionStatus::Success || count.data.size() != 2) {
        ESP_LOGE(kLogTag, "R558S template count query failed (%d, confirmation 0x%02X)",
                 static_cast<int>(count.status), count.confirmation_code);
        return;
    }
    const uint16_t template_count = (static_cast<uint16_t>(count.data[0]) << 8) | count.data[1];
    ESP_LOGI(kLogTag, "R558S reports %u stored template(s)", template_count);
}

}

void FingerprintTask::start()
{
    indication_queue_ = xQueueCreate(1, sizeof(ProvisioningIndicatorState));
    configASSERT(indication_queue_ != nullptr);
    xTaskCreate(task_entry, "fingerprint", 4096, this, 5, nullptr);
}

void FingerprintTask::set_provisioning(ProvisioningIndicatorState state)
{
    if (indication_queue_ != nullptr) xQueueOverwrite(indication_queue_, &state);
}

void FingerprintTask::task_entry(void* context)
{
    static_cast<FingerprintTask*>(context)->run();
}

void FingerprintTask::run()
{
    driver_.initialize();
    log_database(driver_);

    IndicatorScheduler indicator;
    IndicatorColor applied_color = IndicatorColor::Off;
    bool touch_was_active = gpio_get_level(static_cast<gpio_num_t>(kTouchOutGpio));
    while (true) {
        ProvisioningIndicatorState state;
        if (xQueueReceive(indication_queue_, &state, 0) == pdTRUE) indicator.set_provisioning(state);

        const bool touch_is_active = gpio_get_level(static_cast<gpio_num_t>(kTouchOutGpio));
        if (touch_is_active && !touch_was_active) ESP_LOGI(kLogTag, "R558S touch detected");
        touch_was_active = touch_is_active;

        const IndicatorColor next_color = indicator.update(esp_timer_get_time() / 1000);
        if (next_color != applied_color) {
            const r558s::TransactionResult result = driver_.set_led(led_color(next_color));
            if (result.status != r558s::TransactionStatus::Success) {
                ESP_LOGE(kLogTag, "R558S LED command failed (%d, confirmation 0x%02X)",
                         static_cast<int>(result.status), result.confirmation_code);
            }
            applied_color = next_color;
        }
        vTaskDelay(kPollDelay);
    }
}

}
