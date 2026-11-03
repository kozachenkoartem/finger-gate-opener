#include "wifi_lifecycle.hpp"

#include <algorithm>

namespace fg {
uint32_t WifiLifecycle::next_attempt()
{
    if (++attempt_id_ == 0) ++attempt_id_;
    return attempt_id_;
}

void WifiLifecycle::clear_ip()
{
    status_.connected = false;
    status_.sta_ip.clear();
}

bool WifiLifecycle::initialize(uint64_t now)
{
    if (initialized_) return true;
    const auto loaded = config_.load_wifi(&saved_);
    if ((loaded != StoreResult::Ok && loaded != StoreResult::NotFound) ||
        config_.load_ap_password(&ap_password_, &status_.custom_ap_password) != StoreResult::Ok) {
        status_.state = "failed";
        status_.message = "Network configuration storage unavailable";
        return false;
    }
    have_saved_ = loaded == StoreResult::Ok;
    initialized_ = true;
    if (have_saved_) connect_saved(Attempt::Saved, now);
    else {
        if (!port_.open_ap(ap_password_)) {
            initialized_ = false;
            status_.state = "failed";
            status_.message = "Unable to start setup access point";
            return false;
        }
        status_.ap_active = true;
        status_.state = "ap_ready";
        status_.message = "Setup access point is ready";
        status_.indication = ProvisioningIndication::AccessPoint;
    }
    return true;
}

void WifiLifecycle::connect_saved(Attempt kind, uint64_t now)
{
    clear_ip();
    attempt_kind_ = kind;
    attempt_deadline_ = now + kAttemptMs;
    status_.state = kind == Attempt::Restore ? "restoring" : "reconnecting";
    status_.ssid = saved_.ssid;
    if (kind != Attempt::Restore) {
        status_.message = "Connecting to saved Wi-Fi";
        status_.indication = ProvisioningIndication::Connecting;
    }
    if (!port_.connect(saved_, next_attempt())) {
        attempt_kind_ = Attempt::None;
        retry_at_ = now + kRetryMs;
        status_.message = "Unable to start saved Wi-Fi connection; retrying";
    }
}

NetworkResult WifiLifecycle::open_recovery(uint64_t now)
{
    if (!initialized_) return NetworkResult::NotReady;
    if (status_.ap_active || status_.trial) return NetworkResult::Busy;
    if (!port_.open_ap(ap_password_)) {
        if (port_.ap_restarted_station() && have_saved_) connect_saved(Attempt::Restore, now);
        return NetworkResult::DriverFailed;
    }
    status_.ap_active = true;
    status_.recovery = true;
    status_.ap_closing = false;
    status_.ap_deadline_ms = now + kApLifetimeMs;
    close_retry_at_ = 0;
    status_.message = "Recovery access point enabled for five minutes";
    status_.indication = ProvisioningIndication::AccessPoint;
    if (port_.ap_restarted_station() && have_saved_) {
        connect_saved(Attempt::Saved, now);
        status_.message = "Recovery AP enabled; reconnecting station after AP password update";
    }
    return NetworkResult::Ok;
}

NetworkResult WifiLifecycle::set_ap_password(const std::string& password)
{
    if (!initialized_) return NetworkResult::NotReady;
    if (status_.ap_active || status_.trial) return NetworkResult::Busy;
    if (!valid_ap_password(password)) return NetworkResult::Invalid;
    if (config_.save_ap_password(password) != StoreResult::Ok) return NetworkResult::StorageFailed;
    ap_password_ = password;
    status_.custom_ap_password = true;
    status_.message = "Individual access point password saved";
    return NetworkResult::Ok;
}

NetworkResult WifiLifecycle::configure_wifi(const WifiCredentials& credentials, uint64_t now)
{
    if (!initialized_) return NetworkResult::NotReady;
    if (!status_.ap_active || status_.trial || status_.ap_closing) return NetworkResult::Busy;
    if (!valid_wifi_credentials(credentials)) return NetworkResult::Invalid;
    candidate_ = credentials;
    failure_indication_until_ = 0;
    clear_ip();
    status_.trial = true;
    status_.last_trial = "connecting";
    status_.ssid = candidate_.ssid;
    status_.state = "connecting";
    status_.message = "Testing new Wi-Fi; previous credentials are preserved";
    status_.indication = ProvisioningIndication::Connecting;
    attempt_kind_ = Attempt::Trial;
    attempt_deadline_ = now + kAttemptMs;
    if (!port_.connect(candidate_, next_attempt())) fail_trial(now, "Unable to start new Wi-Fi; restoring previous network");
    return NetworkResult::Ok;
}

void WifiLifecycle::fail_trial(uint64_t now, const char* message)
{
    candidate_ = {};
    status_.trial = false;
    status_.last_trial = "failed";
    status_.message = message;
    status_.indication = ProvisioningIndication::Failed;
    failure_indication_until_ = now + kFailureSignalMs;
    clear_ip();
    attempt_kind_ = Attempt::None;
    if (have_saved_) connect_saved(Attempt::Restore, now);
    else {
        port_.disconnect();
        status_.state = "failed";
        status_.ssid.clear();
    }
}

void WifiLifecycle::got_ip(uint32_t attempt, const std::string& ip, uint64_t now)
{
    if (attempt != attempt_id_ || ip.empty() || (attempt_kind_ == Attempt::None && !status_.connected)) return;
    if (attempt_kind_ == Attempt::Trial && (now >= attempt_deadline_ ||
        (status_.recovery && status_.ap_deadline_ms && now >= status_.ap_deadline_ms))) {
        fail_trial(now, "New Wi-Fi result arrived after the allowed window; restoring previous network");
        return;
    }
    if (attempt_kind_ == Attempt::Trial) {
        if (config_.save_wifi(candidate_) != StoreResult::Ok) {
            fail_trial(now, "Unable to save new settings; restoring previous network");
            return;
        }
        saved_ = std::move(candidate_);
        have_saved_ = true;
        status_.trial = false;
        status_.last_trial = "success";
        status_.message = "New Wi-Fi connected and saved";
        status_.indication = ProvisioningIndication::Connected;
        failure_indication_until_ = 0;
        if (!status_.ap_deadline_ms) status_.ap_deadline_ms = now + kApLifetimeMs;
    } else {
        status_.message = status_.last_trial == "failed" ? "Previous Wi-Fi restored; new settings were not saved" : "Connected to the local network";
        if (!failure_indication_until_ || now >= failure_indication_until_)
            status_.indication = status_.ap_active && status_.last_trial != "success" ? ProvisioningIndication::AccessPoint : ProvisioningIndication::Connected;
    }
    status_.state = "connected";
    status_.connected = true;
    status_.sta_ip = ip;
    status_.ssid = saved_.ssid;
    attempt_kind_ = Attempt::None;
}

void WifiLifecycle::disconnected(uint32_t attempt, uint64_t now)
{
    if (attempt != attempt_id_) return;
    if (attempt_kind_ == Attempt::Trial) {
        fail_trial(now, "New Wi-Fi failed; restoring previous network");
        return;
    }
    clear_ip();
    attempt_kind_ = Attempt::None;
    retry_at_ = now + kRetryMs;
    status_.state = "reconnecting";
    status_.message = "Wi-Fi disconnected; reconnecting to saved network";
    status_.indication = ProvisioningIndication::Failed;
    failure_indication_until_ = now + kFailureSignalMs;
}

void WifiLifecycle::event_loss(uint64_t now)
{
    if (status_.trial) fail_trial(now, "Wi-Fi event loss; restoring previous network");
    else if (have_saved_) {
        status_.message = "Wi-Fi event loss; verifying saved connection again";
        connect_saved(Attempt::Restore, now);
    } else {
        clear_ip();
        attempt_kind_ = Attempt::None;
        port_.disconnect();
        status_.state = "failed";
        status_.message = "Wi-Fi events lost; retry setup";
        status_.indication = ProvisioningIndication::Failed;
    }
}

NetworkResult WifiLifecycle::acknowledge(uint64_t now)
{
    if (!status_.ap_active || !status_.connected || status_.trial) return NetworkResult::Busy;
    const auto deadline = now + 500;
    status_.ap_deadline_ms = status_.ap_deadline_ms ? std::min(deadline, status_.ap_deadline_ms) : deadline;
    return NetworkResult::Ok;
}

void WifiLifecycle::poll(uint64_t now)
{
    if (!initialized_) return;
    if (failure_indication_until_ && now >= failure_indication_until_) {
        failure_indication_until_ = 0;
        status_.indication = status_.trial ? ProvisioningIndication::Connecting : status_.ap_active
            ? (status_.last_trial == "success" ? ProvisioningIndication::Connected : ProvisioningIndication::AccessPoint)
            : (status_.connected ? ProvisioningIndication::Idle : ProvisioningIndication::Connecting);
    }
    if (attempt_kind_ != Attempt::None && now >= attempt_deadline_) {
        if (attempt_kind_ == Attempt::Trial) fail_trial(now, "New Wi-Fi timed out; restoring previous network");
        else {
            port_.disconnect();
            attempt_kind_ = Attempt::None;
            clear_ip();
            retry_at_ = now + kRetryMs;
            status_.state = "reconnecting";
            status_.message = "Saved Wi-Fi not available; retrying";
        }
    }
    if (attempt_kind_ == Attempt::None && !status_.connected && have_saved_ && now >= retry_at_)
        connect_saved(status_.last_trial == "failed" ? Attempt::Restore : Attempt::Saved, now);
    if (status_.ap_active && status_.ap_deadline_ms && now >= status_.ap_deadline_ms && now >= close_retry_at_) {
        if (status_.trial) fail_trial(now, "Recovery window expired; restoring previous network");
        status_.ap_closing = true;
        if (port_.close_ap()) {
            status_.ap_active = false;
            status_.recovery = false;
            status_.ap_closing = false;
            status_.ap_deadline_ms = 0;
            if (!failure_indication_until_) status_.indication = status_.connected ? ProvisioningIndication::Idle : ProvisioningIndication::Connecting;
        } else close_retry_at_ = now + 1000;
    }
}
}
