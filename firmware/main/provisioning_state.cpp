#include "provisioning_state.hpp"

#include <cctype>

namespace fg {
namespace {

bool decode_component(const std::string& encoded, std::string* decoded)
{
    decoded->clear();
    decoded->reserve(encoded.size());
    for (size_t index = 0; index < encoded.size(); ++index) {
        const char character = encoded[index];
        if (character == '+') {
            decoded->push_back(' ');
            continue;
        }
        if (character != '%') {
            decoded->push_back(character);
            continue;
        }
        if (index + 2 >= encoded.size() || !std::isxdigit(static_cast<unsigned char>(encoded[index + 1])) ||
            !std::isxdigit(static_cast<unsigned char>(encoded[index + 2]))) {
            return false;
        }
        const auto hex_value = [](char digit) {
            if (digit >= '0' && digit <= '9') return digit - '0';
            return std::tolower(static_cast<unsigned char>(digit)) - 'a' + 10;
        };
        decoded->push_back(static_cast<char>((hex_value(encoded[index + 1]) << 4) | hex_value(encoded[index + 2])));
        index += 2;
    }
    return true;
}

std::string json_escape(const std::string& value)
{
    std::string escaped;
    escaped.reserve(value.size());
    for (const char character : value) {
        switch (character) {
        case '"': escaped += "\\\""; break;
        case '\\': escaped += "\\\\"; break;
        case '\b': escaped += "\\b"; break;
        case '\f': escaped += "\\f"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default: escaped += character; break;
        }
    }
    return escaped;
}

}

FormDecodeResult decode_wifi_form(const std::string& body)
{
    FormDecodeResult result;
    bool has_ssid = false;
    bool has_password = false;
    size_t start = 0;
    while (start <= body.size()) {
        const size_t end = body.find('&', start);
        const std::string field = body.substr(start, end - start);
        const size_t separator = field.find('=');
        if (separator == std::string::npos) {
            result.error = "invalid form field";
            return result;
        }
        std::string name;
        std::string value;
        if (!decode_component(field.substr(0, separator), &name) ||
            !decode_component(field.substr(separator + 1), &value)) {
            result.error = "invalid URL encoding";
            return result;
        }
        if (name == "ssid") {
            if (has_ssid) {
                result.error = "duplicate SSID";
                return result;
            }
            result.credentials.ssid = std::move(value);
            has_ssid = true;
        } else if (name == "password") {
            if (has_password) {
                result.error = "duplicate password";
                return result;
            }
            result.credentials.password = std::move(value);
            has_password = true;
        } else {
            result.error = "unknown form field";
            return result;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    if (!has_ssid || result.credentials.ssid.empty() || result.credentials.ssid.size() > 32 ||
        result.credentials.password.size() > 63) {
        result.error = "invalid Wi-Fi settings";
    }
    return result;
}

ProvisioningState::ProvisioningState(std::string ap_ip, std::string hostname)
    : ap_ip_(std::move(ap_ip)), hostname_(std::move(hostname))
{
}

void ProvisioningState::set_network_details(std::string ap_ip, std::string hostname)
{
    ap_ip_ = std::move(ap_ip);
    hostname_ = std::move(hostname);
}

void ProvisioningState::ap_ready()
{
    phase_ = Phase::ApReady;
    message_ = "Access point is ready";
    station_ip_.clear();
}

void ProvisioningState::connecting()
{
    phase_ = Phase::Connecting;
    message_ = "Connecting to the selected Wi-Fi network";
    station_ip_.clear();
}

void ProvisioningState::connected(const std::string& station_ip)
{
    phase_ = Phase::Connected;
    message_ = "Connected to the local network";
    station_ip_ = station_ip;
}

void ProvisioningState::failed(const std::string& reason)
{
    phase_ = Phase::Failed;
    message_ = reason;
    station_ip_.clear();
}

const char* ProvisioningState::phase_name(Phase phase)
{
    switch (phase) {
    case Phase::ApReady: return "ap_ready";
    case Phase::Connecting: return "connecting";
    case Phase::Connected: return "connected";
    case Phase::Failed: return "failed";
    }
    return "failed";
}

std::string ProvisioningState::json() const
{
    return "{\"state\":\"" + std::string(phase_name(phase_)) + "\",\"message\":\"" + json_escape(message_) +
           "\",\"sta_ip\":\"" + json_escape(station_ip_) + "\",\"ap_ip\":\"" + json_escape(ap_ip_) +
           "\",\"hostname\":\"" + json_escape(hostname_) + "\"}";
}

}
