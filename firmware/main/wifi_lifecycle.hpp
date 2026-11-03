#pragma once

#include "config_store.hpp"
#include "indicator.hpp"

namespace fg {
enum class NetworkResult { Ok, Busy, Invalid, StorageFailed, DriverFailed, NotReady };

class NetworkPort {
public:
    virtual ~NetworkPort() = default;
    virtual bool open_ap(const std::string& password) = 0;
    virtual bool close_ap() = 0;
    virtual bool connect(const WifiCredentials& credentials, uint32_t attempt) = 0;
    virtual bool disconnect() = 0;
    virtual bool ap_restarted_station() const { return false; }
};

struct WifiStatus {
    std::string state = "initializing";
    std::string message = "Initializing Wi-Fi";
    std::string sta_ip;
    std::string ssid;
    std::string last_trial;
    bool connected = false;
    bool ap_active = false;
    bool recovery = false;
    bool ap_closing = false;
    bool custom_ap_password = false;
    bool trial = false;
    uint64_t ap_deadline_ms = 0;
    ProvisioningIndication indication = ProvisioningIndication::Idle;
};

class WifiLifecycle {
public:
    WifiLifecycle(KeyValueStore& storage, NetworkPort& port) : config_(storage), port_(port) {}
    bool initialize(uint64_t now);
    NetworkResult open_recovery(uint64_t now);
    NetworkResult configure_wifi(const WifiCredentials& credentials, uint64_t now);
    NetworkResult set_ap_password(const std::string& password);
    NetworkResult acknowledge(uint64_t now);
    void got_ip(uint32_t attempt, const std::string& ip, uint64_t now);
    void disconnected(uint32_t attempt, uint64_t now);
    void event_loss(uint64_t now);
    void poll(uint64_t now);
    const WifiStatus& status() const { return status_; }

private:
    enum class Attempt { None, Saved, Trial, Restore };
    static constexpr auto kApLifetimeMs = uint64_t{300000};
    static constexpr auto kAttemptMs = uint64_t{30000};
    static constexpr auto kRetryMs = uint64_t{5000};
    static constexpr auto kFailureSignalMs = uint64_t{1200};
    void connect_saved(Attempt kind, uint64_t now);
    void fail_trial(uint64_t now, const char* message);
    void clear_ip();
    uint32_t next_attempt();

    ConfigStore config_;
    NetworkPort& port_;
    WifiStatus status_;
    WifiCredentials saved_;
    WifiCredentials candidate_;
    std::string ap_password_;
    Attempt attempt_kind_ = Attempt::None;
    uint32_t attempt_id_ = 0;
    uint64_t attempt_deadline_ = 0;
    uint64_t retry_at_ = 0;
    uint64_t close_retry_at_ = 0;
    uint64_t failure_indication_until_ = 0;
    bool have_saved_ = false;
    bool initialized_ = false;
};
}
