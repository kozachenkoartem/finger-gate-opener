#pragma once

#include <string>
#include <vector>
#include "user_store.hpp"

namespace fg {
class TlsIdentity {
public:
    bool initialize(KeyValueStore& storage, const std::string& hostname);
    const std::vector<uint8_t>& certificate() const { return certificate_; }
    const std::vector<uint8_t>& private_key() const { return key_; }

private:
    bool generate(const std::string& hostname);
    bool validate() const;
    std::vector<uint8_t> certificate_;
    std::vector<uint8_t> key_;
};
}
