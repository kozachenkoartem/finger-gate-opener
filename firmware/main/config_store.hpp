#pragma once

#include "provisioning_state.hpp"
#include "user_store.hpp"

namespace fg {

bool should_start_provisioning(StoreResult credentials_result);
bool valid_wifi_credentials(const WifiCredentials& credentials);
bool valid_ap_password(const std::string& password);

class ConfigStore {
public:
    explicit ConfigStore(KeyValueStore& storage) : storage_(storage) {}

    StoreResult save_wifi(const WifiCredentials& credentials);
    StoreResult load_wifi(WifiCredentials* credentials) const;
    StoreResult save_ap_password(const std::string& password);
    StoreResult load_ap_password(std::string* password, bool* custom) const;

private:
    KeyValueStore& storage_;
};

}
