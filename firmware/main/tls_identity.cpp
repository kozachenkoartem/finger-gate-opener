#include "tls_identity.hpp"

#include <array>
#include <cstring>
#include "esp_random.h"
#include "mbedtls/ecp.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"

namespace fg {
namespace {
constexpr char kIdentityKey[] = "tls_identity";
constexpr size_t kMaxPemSize = 2048;
constexpr size_t kRecordHeader = 3;

int random_bytes(void*, unsigned char* output, size_t size)
{
    esp_fill_random(output, size);
    return 0;
}
}

bool TlsIdentity::initialize(KeyValueStore& storage, const std::string& hostname)
{
    std::vector<uint8_t> bytes;
    const StoreResult result = storage.get(kIdentityKey, &bytes);
    if (result == StoreResult::Ok) {
        if (bytes.size() < kRecordHeader || bytes.size() > 2 * kMaxPemSize + kRecordHeader || bytes[0] != 1) return false;
        const size_t cert_size = (static_cast<size_t>(bytes[1]) << 8) | bytes[2];
        if (cert_size == 0 || cert_size > kMaxPemSize || kRecordHeader + cert_size >= bytes.size()) return false;
        certificate_.assign(bytes.begin() + kRecordHeader, bytes.begin() + kRecordHeader + cert_size);
        key_.assign(bytes.begin() + kRecordHeader + cert_size, bytes.end());
        return validate();
    }
    if (result != StoreResult::NotFound || !generate(hostname) || !validate()) return false;
    bytes = {1, static_cast<uint8_t>(certificate_.size() >> 8), static_cast<uint8_t>(certificate_.size())};
    bytes.insert(bytes.end(), certificate_.begin(), certificate_.end());
    bytes.insert(bytes.end(), key_.begin(), key_.end());
    return storage.put(kIdentityKey, bytes) == StoreResult::Ok;
}

bool TlsIdentity::validate() const
{
    if (certificate_.empty() || key_.empty() || certificate_.back() != 0 || key_.back() != 0) return false;
    mbedtls_x509_crt cert;
    mbedtls_pk_context key;
    mbedtls_x509_crt_init(&cert);
    mbedtls_pk_init(&key);
    const bool valid = mbedtls_x509_crt_parse(&cert, certificate_.data(), certificate_.size()) == 0 &&
        mbedtls_pk_parse_key(&key, key_.data(), key_.size(), nullptr, 0, random_bytes, nullptr) == 0 &&
        mbedtls_pk_check_pair(&cert.pk, &key, random_bytes, nullptr) == 0;
    mbedtls_pk_free(&key);
    mbedtls_x509_crt_free(&cert);
    return valid;
}

bool TlsIdentity::generate(const std::string& hostname)
{
    mbedtls_pk_context key;
    mbedtls_x509write_cert cert;
    std::array<unsigned char, 16> serial{};
    mbedtls_pk_init(&key);
    mbedtls_x509write_crt_init(&cert);
    esp_fill_random(serial.data(), serial.size());
    serial[0] = (serial[0] & 0x7f) | 1;
    std::array<unsigned char, kMaxPemSize> cert_pem{};
    std::array<unsigned char, kMaxPemSize> key_pem{};
    const std::string domain = hostname + ".local";
    const std::string subject = "CN=" + domain + ",O=Finger Gate";
    // DER SubjectAlternativeName: одно DNS-имя устройства.
    std::vector<unsigned char> san{0x30, static_cast<unsigned char>(domain.size() + 2), 0x82, static_cast<unsigned char>(domain.size())};
    san.insert(san.end(), domain.begin(), domain.end());
    mbedtls_x509write_crt_set_version(&cert, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA256);
    bool ok = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) == 0;
    if (ok) ok = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key), random_bytes, nullptr) == 0;
    if (ok) {
        mbedtls_x509write_crt_set_subject_key(&cert, &key);
        mbedtls_x509write_crt_set_issuer_key(&cert, &key);
        ok = mbedtls_x509write_crt_set_serial_raw(&cert, serial.data(), serial.size()) == 0 &&
             mbedtls_x509write_crt_set_subject_name(&cert, subject.c_str()) == 0 &&
             mbedtls_x509write_crt_set_issuer_name(&cert, subject.c_str()) == 0 &&
             mbedtls_x509write_crt_set_validity(&cert, "20240101000000", "20491231235959") == 0 &&
             mbedtls_x509write_crt_set_basic_constraints(&cert, 0, -1) == 0 &&
             mbedtls_x509write_crt_set_key_usage(&cert, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) == 0 &&
             mbedtls_x509write_crt_set_extension(&cert, MBEDTLS_OID_SUBJECT_ALT_NAME,
                 MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME), 0, san.data(), san.size()) == 0 &&
             mbedtls_x509write_crt_pem(&cert, cert_pem.data(), cert_pem.size(), random_bytes, nullptr) == 0 &&
             mbedtls_pk_write_key_pem(&key, key_pem.data(), key_pem.size()) == 0;
    }
    if (ok) {
        certificate_.assign(cert_pem.begin(), cert_pem.begin() + std::strlen(reinterpret_cast<char*>(cert_pem.data())) + 1);
        key_.assign(key_pem.begin(), key_pem.begin() + std::strlen(reinterpret_cast<char*>(key_pem.data())) + 1);
    }
    mbedtls_pk_free(&key);
    mbedtls_x509write_crt_free(&cert);
    return ok;
}
}
