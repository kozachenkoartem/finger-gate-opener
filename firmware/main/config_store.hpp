#pragma once

#include "provisioning_state.hpp"
#include "user_store.hpp"

namespace fg {

bool should_start_provisioning(StoreResult credentials_result);

class ConfigStore {
public:
    explicit ConfigStore(KeyValueStore& storage) : storage_(storage) {}

    StoreResult save_wifi(const WifiCredentials& credentials);
    StoreResult load_wifi(WifiCredentials* credentials) const;

private:
    KeyValueStore& storage_;
};

}
