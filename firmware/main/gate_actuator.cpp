#include "gate_actuator.hpp"

#include "driver/gpio.h"
#include "esp_attr.h"
#include "esp_check.h"
#include "esp_timer.h"

#if !CONFIG_GPTIMER_ISR_CACHE_SAFE || !CONFIG_GPIO_CTRL_FUNC_IN_IRAM || !CONFIG_GPTIMER_CTRL_FUNC_IN_IRAM
#error "Gate pulse requires cache-safe GPTimer and IRAM GPIO control"
#endif

namespace fg {
namespace {
constexpr gpio_num_t kGateLed = GPIO_NUM_8;
constexpr uint32_t kInactiveLevel = 1;
constexpr uint32_t kActiveLevel = 0;
constexpr uint32_t kTimerHz = 1000000;
constexpr uint64_t kPulseTicks = 1000000;
constexpr char kLogTag[] = "gate_led";
}

esp_err_t GateActuator::initialize()
{
    // Сначала задаём неактивный уровень, затем включаем выход. GPIO10 не трогаем.
    ESP_RETURN_ON_ERROR(gpio_set_level(kGateLed, kInactiveLevel), kLogTag, "inactive level failed");
    gpio_config_t gpio = {};
    gpio.pin_bit_mask = 1ULL << kGateLed;
    gpio.mode = GPIO_MODE_OUTPUT;
    ESP_RETURN_ON_ERROR(gpio_config(&gpio), kLogTag, "GPIO8 initialization failed");
    gptimer_config_t config = {};
    config.clk_src = GPTIMER_CLK_SRC_DEFAULT;
    config.direction = GPTIMER_COUNT_UP;
    config.resolution_hz = kTimerHz;
    config.intr_priority = 3;
    ESP_RETURN_ON_ERROR(gptimer_new_timer(&config, &timer_), kLogTag, "hardware timer failed");
    const gptimer_event_callbacks_t callbacks = {.on_alarm = alarm};
    ESP_RETURN_ON_ERROR(gptimer_register_event_callbacks(timer_, &callbacks, this), kLogTag, "timer callback failed");
    ESP_RETURN_ON_ERROR(gptimer_enable(timer_), kLogTag, "timer enable failed");
    ESP_RETURN_ON_ERROR(gptimer_start(timer_), kLogTag, "timer start failed");
    ready_ = true;
    return ESP_OK;
}

bool IRAM_ATTR GateActuator::alarm(gptimer_handle_t, const gptimer_alarm_event_data_t*, void* context)
{
    auto* gate = static_cast<GateActuator*>(context);
    portENTER_CRITICAL_ISR(&gate->pulse_mux_);
    gpio_set_level(kGateLed, kInactiveLevel);
    gate->active_ = false;
    portEXIT_CRITICAL_ISR(&gate->pulse_mux_);
    return false;
}

PulseResult GateActuator::pulse()
{
    if (!ready_) return {};
    // Нельзя допустить вытеснение между постановкой alarm и включением выхода.
    portENTER_CRITICAL(&pulse_mux_);
    if (active_) { portEXIT_CRITICAL(&pulse_mux_); return {}; }
    active_ = true;
    uint64_t count = 0;
    gptimer_alarm_config_t alarm_config = {};
    esp_err_t result = gptimer_get_raw_count(timer_, &count);
    alarm_config.alarm_count = count + kPulseTicks;
    if (result == ESP_OK) result = gptimer_set_alarm_action(timer_, &alarm_config);
    if (result != ESP_OK) {
        gpio_set_level(kGateLed, kInactiveLevel);
        active_ = false;
        portEXIT_CRITICAL(&pulse_mux_);
        return {};
    }
    const uint64_t started_ms = esp_timer_get_time() / 1000;
    gpio_set_level(kGateLed, kActiveLevel);
    portEXIT_CRITICAL(&pulse_mux_);
    ESP_LOGI(kLogTag, "Access pulse: GPIO8 active for 1000 ms");
    return {true, started_ms};
}
}
