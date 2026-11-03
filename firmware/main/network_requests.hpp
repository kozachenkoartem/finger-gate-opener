#pragma once

#include <cstring>
#include <optional>
#include "wifi_lifecycle.hpp"

namespace fg {
enum class NetworkOperation { Recovery, Configure, ApPassword, Acknowledge };

struct NetworkRequest {
    uint32_t id = 0;
    NetworkOperation operation = NetworkOperation::Recovery;
    char ssid[33] = {};
    char password[64] = {};
    bool active = false;
    uint64_t execute_at = 0;
};

// Вызывающий код сериализует доступ; после резервирования ответ отправляется до активации.
class NetworkRequests {
public:
    uint32_t reserve(NetworkOperation operation, const WifiCredentials& credentials, const std::string& password, const WifiStatus& status)
    {
        if (pending_.id || status.state == "initializing") return 0;
        if ((operation == NetworkOperation::Configure && !valid_wifi_credentials(credentials)) ||
            (operation == NetworkOperation::ApPassword && !valid_ap_password(password))) return 0;
        const bool eligible = operation == NetworkOperation::Recovery ? !status.ap_active && !status.trial :
            operation == NetworkOperation::ApPassword ? !status.ap_active && !status.trial :
            operation == NetworkOperation::Configure ? status.ap_active && !status.trial && !status.ap_closing :
            status.ap_active && status.connected && !status.trial;
        if (!eligible) return 0;
        pending_ = {};
        pending_.id = next_++;
        if (!pending_.id) pending_.id = next_++;
        pending_.operation = operation;
        if (operation == NetworkOperation::Configure) {
            std::memcpy(pending_.ssid, credentials.ssid.data(), credentials.ssid.size());
            std::memcpy(pending_.password, credentials.password.data(), credentials.password.size());
        } else if (operation == NetworkOperation::ApPassword) std::memcpy(pending_.password, password.data(), password.size());
        last_id_ = pending_.id;
        last_result_ = "reserved";
        return pending_.id;
    }

    void finish_response(uint32_t id, bool sent, uint64_t now)
    {
        if (!id || pending_.id != id) return;
        if (sent) { pending_.active = true; pending_.execute_at = now + 500; last_result_ = "queued"; }
        else { pending_ = {}; last_result_ = "response_failed"; }
    }

    std::optional<NetworkRequest> take(uint64_t now)
    {
        if (!pending_.id || !pending_.active || now < pending_.execute_at) return std::nullopt;
        const auto command = pending_;
        pending_ = {};
        return command;
    }

    void completed(uint32_t id, const std::string& result) { if (id == last_id_) last_result_ = result; }
    uint32_t last_id() const { return last_id_; }
    const std::string& last_result() const { return last_result_; }

private:
    NetworkRequest pending_;
    uint32_t next_ = 1;
    uint32_t last_id_ = 0;
    std::string last_result_;
};
}
