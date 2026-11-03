#include "wifi_event_gate.hpp"

namespace fg {
void WifiEventGate::begin(uint32_t attempt, const std::string& ssid, uint32_t floor)
{
    attempt_ = attempt;
    ssid_ = ssid;
    floor_ = floor;
    phase_ = Phase::Disconnecting;
}

void WifiEventGate::disconnected_already(uint32_t floor)
{
    floor_ = floor;
    phase_ = Phase::Ready;
}

void WifiEventGate::started(uint32_t floor)
{
    floor_ = floor;
    phase_ = Phase::Associating;
}

bool WifiEventGate::associated(uint32_t sequence, const std::string& ssid, const std::array<uint8_t,6>& bssid)
{
    if (phase_ != Phase::Associating || sequence <= floor_ || ssid != ssid_) return false;
    bssid_ = bssid;
    floor_ = sequence;
    phase_ = Phase::Associated;
    return true;
}

uint32_t WifiEventGate::ip(uint32_t sequence, const std::array<uint8_t,6>& bssid) const
{
    return phase_ == Phase::Associated && sequence > floor_ && bssid == bssid_ ? attempt_ : 0;
}

LinkLoss WifiEventGate::disconnected(uint32_t sequence, const std::string& ssid, const std::array<uint8_t,6>& bssid)
{
    if (sequence <= floor_) return LinkLoss::Ignore;
    if (phase_ == Phase::Disconnecting) { phase_ = Phase::Ready; floor_ = sequence; return LinkLoss::Boundary; }
    if (ssid != ssid_) return LinkLoss::Ignore;
    if (phase_ == Phase::Associated && bssid != bssid_) return LinkLoss::Ignore;
    if (phase_ != Phase::Associated && phase_ != Phase::Associating) return LinkLoss::Ignore;
    phase_ = Phase::Idle;
    return LinkLoss::Connection;
}
}
