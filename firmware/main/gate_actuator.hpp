#pragma once

#include "driver/gptimer.h"
#include "freertos/FreeRTOS.h"
#include "fingerprint_controller.hpp"

namespace fg {
class GateActuator final : public FingerprintGate {
public:
    esp_err_t initialize();
    PulseResult pulse() override;

private:
    static bool alarm(gptimer_handle_t, const gptimer_alarm_event_data_t*, void*);
    gptimer_handle_t timer_ = nullptr;
    bool active_ = false;
    bool ready_ = false;
    portMUX_TYPE pulse_mux_ = portMUX_INITIALIZER_UNLOCKED;
};
}
