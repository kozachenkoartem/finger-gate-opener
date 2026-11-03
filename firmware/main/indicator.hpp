#pragma once

#include <cstdint>

namespace fg {

enum class IndicatorColor { Off, Blue, Green, Red, Yellow };

enum class ProvisioningIndication { Idle, AccessPoint, Connecting, Connected, Failed };

struct ProvisioningIndicatorState {
    ProvisioningIndication indication = ProvisioningIndication::Idle;
    bool access_point_active = false;

    bool operator==(const ProvisioningIndicatorState& other) const
    {
        return indication == other.indication && access_point_active == other.access_point_active;
    }

    bool operator!=(const ProvisioningIndicatorState& other) const { return !(*this == other); }
};

class IndicatorScheduler {
public:
    void set_provisioning(ProvisioningIndicatorState state);
    IndicatorColor update(uint64_t now_ms);

private:
    IndicatorColor base_color(uint64_t now_ms);
    void start_pattern(IndicatorColor color, uint64_t now_ms);

    ProvisioningIndicatorState state_;
    IndicatorColor color_ = IndicatorColor::Off;
    IndicatorColor pattern_color_ = IndicatorColor::Off;
    uint64_t next_transition_ms_ = 0;
    uint64_t next_ap_pulse_ms_ = 0;
    uint8_t flash_count_ = 0;
    bool state_changed_ = true;
    bool start_pattern_ = false;
    bool pattern_active_ = false;
};

}
