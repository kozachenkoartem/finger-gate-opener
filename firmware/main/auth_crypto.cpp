#include "auth_crypto.hpp"

#include <limits>

#ifdef ESP_PLATFORM
#include "esp_random.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/version.h"
#else
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

namespace fg::auth_crypto {

void wipe(uint8_t* data, size_t size)
{
    volatile uint8_t* bytes = data;
    while (size-- != 0) *bytes++ = 0;
}

bool random_bytes(uint8_t* output, size_t size)
{
#ifdef ESP_PLATFORM
    // Приложение запускает Wi-Fi до инициализации аутентификации.
    esp_fill_random(output, size);
    return true;
#else
    return size <= static_cast<size_t>(std::numeric_limits<int>::max()) &&
           RAND_bytes(output, static_cast<int>(size)) == 1;
#endif
}

bool derive_password(const std::string& password, const Salt& salt, Hash* output)
{
    if (output == nullptr || password.size() > static_cast<size_t>(std::numeric_limits<int>::max())) return false;
#ifdef ESP_PLATFORM
#if MBEDTLS_VERSION_NUMBER >= 0x03030000
    const int result = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
        reinterpret_cast<const unsigned char*>(password.data()), password.size(),
        salt.data(), salt.size(), kIterations, output->size(), output->data());
#else
    mbedtls_md_context_t context;
    mbedtls_md_init(&context);
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int result = info == nullptr ? -1 : mbedtls_md_setup(&context, info, 1);
    if (result == 0) {
        result = mbedtls_pkcs5_pbkdf2_hmac(&context,
            reinterpret_cast<const unsigned char*>(password.data()), password.size(),
            salt.data(), salt.size(), kIterations, output->size(), output->data());
    }
    mbedtls_md_free(&context);
#endif
    if (result == 0) return true;
#else
    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
            salt.data(), static_cast<int>(salt.size()), kIterations, EVP_sha256(),
            static_cast<int>(output->size()), output->data()) == 1) return true;
#endif
    wipe(output->data(), output->size());
    return false;
}

bool random_secret(std::string* output)
{
    std::array<uint8_t, kSecretSize> bytes{};
    if (!random_bytes(bytes.data(), bytes.size())) {
        wipe(bytes.data(), bytes.size());
        return false;
    }
    constexpr char kHex[] = "0123456789abcdef";
    output->resize(bytes.size() * 2);
    for (size_t i = 0; i < bytes.size(); ++i) {
        (*output)[i * 2] = kHex[bytes[i] >> 4];
        (*output)[i * 2 + 1] = kHex[bytes[i] & 0x0f];
    }
    wipe(bytes.data(), bytes.size());
    return true;
}

bool constant_time_equal(const uint8_t* left, const uint8_t* right, size_t size)
{
    volatile uint8_t difference = 0;
    for (size_t i = 0; i < size; ++i) difference = static_cast<uint8_t>(difference | (left[i] ^ right[i]));
    return difference == 0;
}

}
