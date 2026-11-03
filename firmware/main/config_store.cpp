#include "config_store.hpp"

namespace fg {
namespace {
constexpr char kWifiCredentialsKey[] = "wifi";

bool valid(const WifiCredentials& credentials)
{
    return !credentials.ssid.empty() && credentials.ssid.size() <= 32 && credentials.password.size() <= 63;
}
}

bool should_start_provisioning(StoreResult credentials_result)
{
    return credentials_result == StoreResult::NotFound;
}

StoreResult ConfigStore::save_wifi(const WifiCredentials& credentials)
{
    if (!valid(credentials)) return StoreResult::Corrupt;
    std::vector<uint8_t> value;
    value.reserve(credentials.ssid.size() + credentials.password.size() + 2);
    value.push_back(static_cast<uint8_t>(credentials.ssid.size()));
    value.push_back(static_cast<uint8_t>(credentials.password.size()));
    value.insert(value.end(), credentials.ssid.begin(), credentials.ssid.end());
    value.insert(value.end(), credentials.password.begin(), credentials.password.end());
    return storage_.put(kWifiCredentialsKey, value);
}

StoreResult ConfigStore::load_wifi(WifiCredentials* credentials) const
{
    std::vector<uint8_t> value;
    const StoreResult result = storage_.get(kWifiCredentialsKey, &value);
    if (result != StoreResult::Ok) return result;
    if (value.size() < 2) return StoreResult::Corrupt;
    const size_t ssid_size = value[0];
    const size_t password_size = value[1];
    if (value.size() != ssid_size + password_size + 2) return StoreResult::Corrupt;
    WifiCredentials loaded{
        std::string(value.begin() + 2, value.begin() + 2 + ssid_size),
        std::string(value.begin() + 2 + ssid_size, value.end()),
    };
    if (!valid(loaded)) return StoreResult::Corrupt;
    *credentials = std::move(loaded);
    return StoreResult::Ok;
}

}
