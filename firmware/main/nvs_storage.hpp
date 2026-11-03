#pragma once

#include "user_store.hpp"

namespace fg {

class NvsKeyValueStore final : public KeyValueStore {
public:
    StoreResult initialize();
    StoreResult get(const std::string& key, std::vector<uint8_t>* value) const override;
    StoreResult put(const std::string& key, const std::vector<uint8_t>& value) override;
    StoreResult erase(const std::string& key) override;
};

}
