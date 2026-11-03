#pragma once

#include <string>

namespace fg {

struct WifiCredentials {
    std::string ssid;
    std::string password;
};

struct FormDecodeResult {
    WifiCredentials credentials;
    std::string error;

    bool ok() const { return error.empty(); }
};

FormDecodeResult decode_wifi_form(const std::string& body);

class ProvisioningState {
public:
    ProvisioningState(std::string ap_ip, std::string hostname);

    void set_network_details(std::string ap_ip, std::string hostname);
    void ap_ready();
    void connecting();
    void connected(const std::string& station_ip);
    void failed(const std::string& reason);
    std::string json() const;

private:
    enum class Phase { ApReady, Connecting, Connected, Failed };

    static const char* phase_name(Phase phase);

    Phase phase_ = Phase::ApReady;
    std::string message_ = "Access point is ready";
    std::string station_ip_;
    std::string ap_ip_;
    std::string hostname_;
};

}
