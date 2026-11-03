#include "config_store.hpp"

#include <algorithm>

namespace fg {
namespace {
constexpr char kWifiKey[] = "wifi";
constexpr char kRollbackKey[] = "wifi_rollback";
constexpr char kApPasswordKey[] = "ap_password";
constexpr char kDefaultApPassword[] = "fingergate";
constexpr uint8_t kVersion = 1;

std::vector<uint8_t> encode_wifi(const WifiCredentials& credentials)
{
    std::vector<uint8_t> bytes{static_cast<uint8_t>(credentials.ssid.size()), static_cast<uint8_t>(credentials.password.size())};
    bytes.insert(bytes.end(), credentials.ssid.begin(), credentials.ssid.end());
    bytes.insert(bytes.end(), credentials.password.begin(), credentials.password.end());
    return bytes;
}

StoreResult decode_wifi(const std::vector<uint8_t>& bytes, WifiCredentials* credentials)
{
    if (bytes.size() < 2 || bytes.size() != static_cast<size_t>(bytes[0]) + bytes[1] + 2) return StoreResult::Corrupt;
    WifiCredentials decoded{std::string(bytes.begin() + 2, bytes.begin() + 2 + bytes[0]),
                            std::string(bytes.begin() + 2 + bytes[0], bytes.end())};
    if (!valid_wifi_credentials(decoded)) return StoreResult::Corrupt;
    *credentials = std::move(decoded);
    return StoreResult::Ok;
}

bool confirmed_put(KeyValueStore& storage, const char* key, const std::vector<uint8_t>& bytes)
{
    const auto result = storage.put(key, bytes);
    if (result == StoreResult::Ok) return true;
    std::vector<uint8_t> observed;
    return storage.get(key, &observed) == StoreResult::Ok && observed == bytes;
}

bool confirmed_erase(KeyValueStore& storage, const char* key)
{
    const auto result = storage.erase(key);
    if (result == StoreResult::Ok || result == StoreResult::NotFound) return true;
    std::vector<uint8_t> observed;
    return storage.get(key, &observed) == StoreResult::NotFound;
}
}

bool valid_wifi_credentials(const WifiCredentials& credentials)
{
    return !credentials.ssid.empty() && credentials.ssid.size() <= 32 && credentials.password.size() <= 63 &&
        credentials.ssid.find('\0') == std::string::npos && credentials.password.find('\0') == std::string::npos;
}

bool valid_ap_password(const std::string& password)
{
    return password.size() >= 8 && password.size() <= 63 &&
        std::all_of(password.begin(), password.end(), [](unsigned char c) { return c >= 0x20 && c <= 0x7e; });
}

bool should_start_provisioning(StoreResult result) { return result == StoreResult::NotFound; }

StoreResult ConfigStore::save_wifi(const WifiCredentials& credentials)
{
    if (!valid_wifi_credentials(credentials)) return StoreResult::Corrupt;
    WifiCredentials old;
    // Не начинаем новую транзакцию поверх незавершённого восстановления.
    const auto loaded = load_wifi(&old);
    if (loaded != StoreResult::Ok && loaded != StoreResult::NotFound) return loaded;
    std::vector<uint8_t> guard{kVersion, static_cast<uint8_t>(loaded == StoreResult::Ok)};
    if (loaded == StoreResult::Ok) {
        const auto previous = encode_wifi(old);
        guard.insert(guard.end(), previous.begin(), previous.end());
    }
    if (!confirmed_put(storage_, kRollbackKey, guard)) return StoreResult::Failed;
    if (!confirmed_put(storage_, kWifiKey, encode_wifi(credentials))) return StoreResult::Failed;
    if (!confirmed_erase(storage_, kRollbackKey)) {
        // Неоднозначное удаление guard не должно запускать разрушительный откат.
        confirmed_put(storage_, kRollbackKey, guard);
        return StoreResult::Failed;
    }
    return StoreResult::Ok;
}

StoreResult ConfigStore::load_wifi(WifiCredentials* credentials) const
{
    std::vector<uint8_t> guard;
    const auto guard_result = storage_.get(kRollbackKey, &guard);
    if (guard_result == StoreResult::Ok) {
        if (guard.size() < 2 || guard[0] != kVersion || guard[1] > 1) return StoreResult::Corrupt;
        WifiCredentials old;
        if (guard[1]) {
            const std::vector<uint8_t> previous(guard.begin() + 2, guard.end());
            if (decode_wifi(previous, &old) != StoreResult::Ok) return StoreResult::Corrupt;
            if (!confirmed_put(storage_, kWifiKey, previous)) return StoreResult::Failed;
        } else {
            if (guard.size() != 2) return StoreResult::Corrupt;
            if (!confirmed_erase(storage_, kWifiKey)) return StoreResult::Failed;
        }
        if (!confirmed_erase(storage_, kRollbackKey)) return StoreResult::Failed;
        *credentials = std::move(old);
        return guard[1] ? StoreResult::Ok : StoreResult::NotFound;
    }
    if (guard_result != StoreResult::NotFound) return guard_result;
    std::vector<uint8_t> bytes;
    const auto result = storage_.get(kWifiKey, &bytes);
    return result == StoreResult::Ok ? decode_wifi(bytes, credentials) : result;
}

StoreResult ConfigStore::save_ap_password(const std::string& password)
{
    if (!valid_ap_password(password)) return StoreResult::Corrupt;
    std::vector<uint8_t> bytes{kVersion};
    bytes.insert(bytes.end(), password.begin(), password.end());
    return confirmed_put(storage_, kApPasswordKey, bytes) ? StoreResult::Ok : StoreResult::Failed;
}

StoreResult ConfigStore::load_ap_password(std::string* password, bool* custom) const
{
    std::vector<uint8_t> bytes;
    const auto result = storage_.get(kApPasswordKey, &bytes);
    if (result == StoreResult::NotFound) {
        *password = kDefaultApPassword;
        *custom = false;
        return StoreResult::Ok;
    }
    if (result != StoreResult::Ok) return result;
    if (bytes.empty() || bytes[0] != kVersion) return StoreResult::Corrupt;
    std::string loaded(bytes.begin() + 1, bytes.end());
    if (!valid_ap_password(loaded)) return StoreResult::Corrupt;
    *password = std::move(loaded);
    *custom = true;
    return StoreResult::Ok;
}
}
