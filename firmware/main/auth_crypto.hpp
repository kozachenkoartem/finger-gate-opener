#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace fg::auth_crypto {

constexpr uint32_t kIterations = 60000;
constexpr size_t kSaltSize = 16;
constexpr size_t kHashSize = 32;
constexpr size_t kSecretSize = 32;

using Salt = std::array<uint8_t, kSaltSize>;
using Hash = std::array<uint8_t, kHashSize>;

bool random_bytes(uint8_t* output, size_t size);
bool derive_password(const std::string& password, const Salt& salt, Hash* output);
bool random_secret(std::string* output);
bool constant_time_equal(const uint8_t* left, const uint8_t* right, size_t size);
void wipe(uint8_t* data, size_t size);

}
