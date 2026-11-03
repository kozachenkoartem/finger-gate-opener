#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace fg {
enum class LinkLoss { Ignore, Boundary, Connection };

class WifiEventGate {
public:
    void begin(uint32_t attempt, const std::string& ssid, uint32_t floor);
    void disconnected_already(uint32_t floor);
    void started(uint32_t floor);
    bool associated(uint32_t sequence, const std::string& ssid, const std::array<uint8_t,6>& bssid);
    uint32_t ip(uint32_t sequence, const std::array<uint8_t,6>& bssid) const;
    LinkLoss disconnected(uint32_t sequence, const std::string& ssid, const std::array<uint8_t,6>& bssid);
    bool ready() const { return phase_ == Phase::Ready; }
    bool disconnecting() const { return phase_ == Phase::Disconnecting; }
    uint32_t attempt() const { return attempt_; }
    void invalidate() { phase_ = Phase::Idle; }

private:
    enum class Phase { Idle, Disconnecting, Ready, Associating, Associated };
    Phase phase_ = Phase::Idle;
    uint32_t attempt_ = 0;
    uint32_t floor_ = 0;
    std::string ssid_;
    std::array<uint8_t,6> bssid_{};
};
}
