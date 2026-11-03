#include "indicator.hpp"

namespace fg {
namespace {

constexpr uint64_t kFlashDurationMs = 200;
constexpr uint64_t kApPulseIntervalMs = 2000;

}

void IndicatorScheduler::set_provisioning(ProvisioningIndicatorState state)
{
    if (state != state_) {
        start_pattern_ = state.indication != state_.indication &&
                         (state.indication == ProvisioningIndication::Connected ||
                          state.indication == ProvisioningIndication::Failed);
        state_ = state;
        state_changed_ = true;
    }
}

IndicatorColor IndicatorScheduler::update(uint64_t now_ms)
{
    if (state_changed_) {
        state_changed_ = false;
        if (start_pattern_) {
            start_pattern(IndicatorColor::Green, now_ms);
        } else if (!pattern_active_) {
            color_ = base_color(now_ms);
        }
        if (state_.indication == ProvisioningIndication::Failed && start_pattern_) {
            pattern_color_ = IndicatorColor::Red;
            color_ = IndicatorColor::Red;
        }
        start_pattern_ = false;
    }

    if (!pattern_active_) {
        if (state_.indication == ProvisioningIndication::Connecting ||
            state_.indication == ProvisioningIndication::Connected || !state_.access_point_active) return color_;
        if (color_ == IndicatorColor::Blue && now_ms >= next_transition_ms_) {
            color_ = IndicatorColor::Off;
        } else if (color_ == IndicatorColor::Off && now_ms >= next_ap_pulse_ms_) {
            color_ = IndicatorColor::Blue;
            next_transition_ms_ = now_ms + kFlashDurationMs;
            next_ap_pulse_ms_ = now_ms + kApPulseIntervalMs;
        }
        return color_;
    }
    while (now_ms >= next_transition_ms_) {
        if (color_ != IndicatorColor::Off) {
            color_ = IndicatorColor::Off;
            next_transition_ms_ += kFlashDurationMs;
            continue;
        }
        if (flash_count_ == 3) {
            pattern_active_ = false;
            color_ = base_color(now_ms);
            break;
        }
        ++flash_count_;
        color_ = pattern_color_;
        next_transition_ms_ += kFlashDurationMs;
    }
    return color_;
}

IndicatorColor IndicatorScheduler::base_color(uint64_t now_ms)
{
    if (state_.indication == ProvisioningIndication::Connecting) return IndicatorColor::Yellow;
    if (!state_.access_point_active) return IndicatorColor::Blue;
    next_ap_pulse_ms_ = now_ms + kApPulseIntervalMs;
    next_transition_ms_ = now_ms + kFlashDurationMs;
    return IndicatorColor::Blue;
}

void IndicatorScheduler::start_pattern(IndicatorColor color, uint64_t now_ms)
{
    pattern_active_ = true;
    pattern_color_ = color;
    color_ = color;
    flash_count_ = 1;
    next_transition_ms_ = now_ms + kFlashDurationMs;
}

}
