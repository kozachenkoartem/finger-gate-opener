#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include "auth.hpp"
#include "auth_crypto.hpp"

namespace {
bool fail_random = false;
bool fail_derivation = false;
int random_calls_before_failure = -1;
constexpr uint64_t kMinute = 60 * 1000;
constexpr uint64_t kIdle = 15 * kMinute;
constexpr uint64_t kAbsolute = 8 * 60 * kMinute;
constexpr char kPassword[] = "correct horse battery staple";

void require(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}

class FaultStore final : public fg::KeyValueStore {
public:
    fg::MemoryKeyValueStore memory;
    fg::StoreResult read_result = fg::StoreResult::Ok;
    bool fail_write = false;
    size_t writes = 0;

    fg::StoreResult get(const std::string& key, std::vector<uint8_t>* value) const override
    {
        return read_result == fg::StoreResult::Ok ? memory.get(key, value) : read_result;
    }
    fg::StoreResult put(const std::string& key, const std::vector<uint8_t>& value) override
    {
        ++writes;
        return fail_write ? fg::StoreResult::Failed : memory.put(key, value);
    }
    fg::StoreResult erase(const std::string& key) override { return memory.erase(key); }
};

fg::Session login(fg::AuthService& auth, uint64_t now = 0, const std::string& password = "admin")
{
    fg::Session session;
    require(auth.login("admin", password, now, &session) == fg::AuthResult::Ok, "valid login must succeed");
    return session;
}

void replace_default(fg::AuthService& auth)
{
    const auto session = login(auth);
    require(auth.change_password(session.token, session.csrf, kPassword, 0) == fg::AuthResult::Ok,
            "default password must be replaceable");
}

bool is_hex_secret(const std::string& value)
{
    return value.size() == 64 && value.find_first_not_of("0123456789abcdef") == std::string::npos;
}

void test_real_crypto()
{
    fg::auth_crypto::Salt salt{};
    fg::auth_crypto::Hash hash{};
    require(fg::auth_crypto::derive_password("password", salt, &hash), "PBKDF2 must work");
    const std::array<uint8_t, 32> expected = {
        0x95, 0x64, 0xdd, 0x26, 0x06, 0x67, 0x7a, 0x17,
        0x79, 0xbc, 0x9e, 0xdf, 0xa1, 0x10, 0xc9, 0x60,
        0xd1, 0x35, 0x81, 0x94, 0x68, 0xd5, 0xd8, 0x14,
        0x46, 0xb2, 0x98, 0xf5, 0x03, 0x3e, 0x36, 0xc6};
    // Эталон получен через Python hashlib.pbkdf2_hmac с теми же входными данными.
    require(hash == expected, "verifier must use SHA256, 60000 iterations and the full salt");
    auto reference = expected;
    require(fg::auth_crypto::constant_time_equal(hash.data(), reference.data(), hash.size()), "equal hashes compare equal");
    reference.back() ^= 1;
    require(!fg::auth_crypto::constant_time_equal(hash.data(), reference.data(), hash.size()), "last-byte mismatch must fail");
}

void test_default_and_persistence()
{
    fg::MemoryKeyValueStore store;
    fg::AuthService auth(store);
    require(auth.initialize() == fg::AuthResult::Ok, "first boot must persist default verifier");
    std::vector<uint8_t> record;
    require(store.get("admin_auth", &record) == fg::StoreResult::Ok, "single admin record must be saved");
    const std::string default_password = "admin";
    require(std::search(record.begin(), record.end(), default_password.begin(), default_password.end()) == record.end(),
            "default record must not contain plaintext");
    fg::MemoryKeyValueStore other_store;
    fg::AuthService other_auth(other_store);
    std::vector<uint8_t> other_record;
    require(other_auth.initialize() == fg::AuthResult::Ok &&
            other_store.get("admin_auth", &other_record) == fg::StoreResult::Ok && record != other_record,
            "fresh devices must have independently salted default verifiers");
    const auto session = login(auth);
    require(session.password_change_required, "default login must require password replacement");
    require(is_hex_secret(session.token) && is_hex_secret(session.csrf) && session.token != session.csrf,
            "token and CSRF must be independent 32-byte random hex secrets");
    require(auth.authorize(session.token, "", false, false, 1) == fg::AuthResult::PasswordChangeRequired,
            "default credentials must not grant normal read access");
    require(auth.authorize(session.token, "", false, true, 1) == fg::AuthResult::Ok,
            "password-change status must be accessible");
    require(auth.authorize(session.token, session.csrf, true, false, 1) == fg::AuthResult::PasswordChangeRequired,
            "default credentials must not grant ordinary mutation access");
    fg::AuthService recreated(store);
    require(recreated.initialize() == fg::AuthResult::Ok, "saved default verifier must load");
    require(login(recreated).password_change_required, "must-change flag must survive recreation");
    require(auth.change_password(session.token, session.csrf, kPassword, 2) == fg::AuthResult::Ok, "password replacement must persist");
    require(auth.authorize(session.token, session.csrf, false, true, 3) == fg::AuthResult::Unauthorized,
            "password replacement must invalidate original session");
    fg::Session output;
    require(auth.login("admin", "admin", 3, &output) == fg::AuthResult::Unauthorized, "old password must stop working");
    fg::AuthService after_change(store);
    require(after_change.initialize() == fg::AuthResult::Ok, "replacement verifier must survive recreation");
    require(!login(after_change, 4, kPassword).password_change_required, "replacement must clear must-change flag persistently");
    require(after_change.login("admin", "admin", 4, &output) == fg::AuthResult::Unauthorized, "old password must stay invalid after recreation");
    require(store.get("admin_auth", &record) == fg::StoreResult::Ok, "replacement record must exist");
    require(std::search(record.begin(), record.end(), kPassword, kPassword + sizeof(kPassword) - 1) == record.end(),
            "replacement record must not contain plaintext");
}

void test_csrf_logout_and_all_session_invalidation()
{
    fg::MemoryKeyValueStore store;
    fg::AuthService auth(store);
    require(auth.initialize() == fg::AuthResult::Ok, "initialize");
    replace_default(auth);
    const auto first = login(auth, 1, kPassword);
    const auto second = login(auth, 1, kPassword);
    require(first.token != second.token && first.csrf != second.csrf, "sessions must have distinct secrets");
    fg::Session output;
    require(auth.authorize(first.token, "", false, false, 2, &output) == fg::AuthResult::Ok && output.csrf == first.csrf,
            "read authorization must return session without requiring CSRF");
    require(auth.authorize(first.token, "wrong", true, false, 2) == fg::AuthResult::Forbidden, "mutation requires matching CSRF");
    require(auth.authorize(first.token, second.csrf, true, false, 2) == fg::AuthResult::Forbidden, "CSRF from another session must fail");
    require(auth.authorize(first.token, first.csrf, true, false, 2) == fg::AuthResult::Ok, "correct mutation CSRF must pass");
    std::string forged = first.token;
    forged.back() = forged.back() == '0' ? '1' : '0';
    require(auth.authorize(forged, first.csrf, true, true, 2) == fg::AuthResult::Unauthorized, "forged bearer must fail");
    require(auth.logout(first.token, "", 3) == fg::AuthResult::Forbidden, "logout requires CSRF");
    require(auth.logout(first.token, first.csrf, 3) == fg::AuthResult::Ok, "logout must work");
    require(auth.authorize(first.token, "", false, false, 3) == fg::AuthResult::Unauthorized, "logged out session must fail");
    require(auth.authorize(second.token, "", false, false, 3) == fg::AuthResult::Ok, "logout must preserve other sessions");
    const auto third = login(auth, 3, kPassword);
    require(auth.change_password(second.token, second.csrf, "a different secure password", 4) == fg::AuthResult::Ok,
            "replacement password must be changeable");
    require(auth.authorize(second.token, "", false, true, 4) == fg::AuthResult::Unauthorized &&
            auth.authorize(third.token, "", false, true, 4) == fg::AuthResult::Unauthorized,
            "password change must invalidate every session");
}

void test_input_and_capacity()
{
    fg::MemoryKeyValueStore store;
    fg::AuthService auth(store);
    require(auth.initialize() == fg::AuthResult::Ok, "initialize");
    const auto session = login(auth);
    for (const auto& password : {std::string{}, std::string("admin"), std::string(11, 'x'),
                                 std::string(129, 'x'), std::string("valid prefix\0suffix", 19)}) {
        require(auth.change_password(session.token, session.csrf, password, 0) == fg::AuthResult::InvalidInput,
                "replacement must reject short/long/default/NUL passwords");
    }
    require(auth.change_password(session.token, "wrong", kPassword, 0) == fg::AuthResult::Forbidden,
            "password replacement requires CSRF even for default credentials");
    fg::Session output{"stale", "stale", true};
    require(auth.login("admin", "admin", 0, nullptr) == fg::AuthResult::InvalidInput, "login requires output");
    require(auth.login("", "admin", 0, &output) == fg::AuthResult::InvalidInput, "empty username must fail");
    require(auth.login("admin", "", 0, &output) == fg::AuthResult::InvalidInput, "empty login password must fail");
    require(auth.login(std::string("admin\0x", 7), "admin", 0, &output) == fg::AuthResult::InvalidInput,
            "username NUL must fail");
    require(output.token.empty() && output.csrf.empty(), "failed login must clear stale output");
    require(auth.login("admin", std::string("admin\0x", 7), 0, &output) == fg::AuthResult::InvalidInput, "password NUL must fail");
    require(auth.login(std::string(129, 'x'), "admin", 0, &output) == fg::AuthResult::InvalidInput, "username input must be bounded");
    require(auth.login("admin", std::string(129, 'x'), 0, &output) == fg::AuthResult::InvalidInput, "login password must be bounded");
    for (int i = 0; i < 3; ++i) login(auth);
    require(auth.login("admin", "admin", 0, &output) == fg::AuthResult::RateLimited, "session table must cap at four");
    require(auth.authorize(session.token, "", false, true, 0) == fg::AuthResult::Ok, "capacity must not evict existing sessions");
    require(auth.logout(session.token, session.csrf, 0) == fg::AuthResult::Ok, "logout must free capacity");
    login(auth);
    require(auth.change_password("missing", "missing", kPassword, 0) == fg::AuthResult::Unauthorized, "missing session cannot change password");

    fg::MemoryKeyValueStore boundaries;
    fg::AuthService bounded(boundaries);
    require(bounded.initialize() == fg::AuthResult::Ok, "initialize boundary test");
    auto current = login(bounded);
    require(bounded.change_password(current.token, current.csrf, std::string(12, 'x'), 0) == fg::AuthResult::Ok, "12 bytes must be allowed");
    current = login(bounded, 0, std::string(12, 'x'));
    require(bounded.change_password(current.token, current.csrf, std::string(128, 'y'), 0) == fg::AuthResult::Ok, "128 bytes must be allowed");
    login(bounded, 0, std::string(128, 'y'));
}

void test_expiry()
{
    fg::MemoryKeyValueStore store;
    fg::AuthService auth(store);
    require(auth.initialize() == fg::AuthResult::Ok, "initialize");
    auto session = login(auth, 100);
    require(auth.authorize(session.token, "", false, true, 100 + kIdle) == fg::AuthResult::Unauthorized, "idle expiry is inclusive");
    session = login(auth, 100 + kIdle);
    require(auth.authorize(session.token, "", false, true, 100 + 2 * kIdle - 1) == fg::AuthResult::Ok, "active session before idle deadline must pass");
    require(auth.authorize(session.token, "", false, true, 100 + 3 * kIdle - 2) == fg::AuthResult::Ok, "successful authorization must roll idle expiry");
    session = login(auth, 10 * kIdle);
    require(auth.authorize(session.token, "bad", true, true, 11 * kIdle - 1) == fg::AuthResult::Forbidden, "bad CSRF rejected");
    require(auth.authorize(session.token, "", false, true, 11 * kIdle) == fg::AuthResult::Unauthorized, "bad CSRF must not refresh idle expiry");
    session = login(auth, 20 * kIdle);
    const uint64_t created = 20 * kIdle;
    for (uint64_t elapsed = kIdle - 1; elapsed < kAbsolute; elapsed += kIdle - 1) {
        require(auth.authorize(session.token, "", false, true, created + elapsed) == fg::AuthResult::Ok, "activity before absolute limit must pass");
    }
    require(auth.authorize(session.token, "", false, true, created + kAbsolute) == fg::AuthResult::Unauthorized, "absolute expiry must not roll");
    session = login(auth, created + kAbsolute);
    require(auth.logout(session.token, session.csrf, created + kAbsolute + kIdle) == fg::AuthResult::Unauthorized, "expired logout must fail");

    fg::MemoryKeyValueStore rollback_store;
    fg::AuthService rollback(rollback_store);
    require(rollback.initialize() == fg::AuthResult::Ok, "initialize rollback test");
    session = login(rollback, 1000);
    require(rollback.authorize(session.token, "", false, true, 999) == fg::AuthResult::Unauthorized, "clock rollback must expire sessions");
}

void test_rate_limiting()
{
    fg::MemoryKeyValueStore store;
    fg::AuthService auth(store);
    require(auth.initialize() == fg::AuthResult::Ok, "initialize");
    fg::Session output;
    for (int i = 0; i < 4; ++i) {
        require(auth.login(i % 2 == 0 ? "unknown" : "admin", "wrong", i, &output) == fg::AuthResult::Unauthorized,
                "unknown names and incorrect passwords must share failure count");
    }
    require(auth.login("unknown", "admin", 4, &output) == fg::AuthResult::RateLimited, "fifth wrong login must lock globally");
    require(auth.login("admin", "admin", 5, &output) == fg::AuthResult::RateLimited, "correct credentials must not bypass lock");
    require(auth.initialize() == fg::AuthResult::Ok, "initialize must be idempotent");
    require(auth.login("admin", "admin", kMinute + 3, &output) == fg::AuthResult::RateLimited, "lock probes and initialize must not shorten lock");
    require(auth.login("admin", "admin", kMinute + 4, &output) == fg::AuthResult::Ok, "probes must not extend 60-second lock");
    for (int i = 0; i < 4; ++i) {
        require(auth.login("unknown", "wrong", kMinute + 5 + i, &output) == fg::AuthResult::Unauthorized, "successful login must reset failure count");
    }
    require(auth.login("admin", "admin", kMinute + 10, &output) == fg::AuthResult::Ok, "four wrong attempts must still allow correct login");
    require(auth.login("admin", "wrong", kMinute + 11, &output) == fg::AuthResult::Unauthorized, "success must reset failure count again");
}

void test_storage_failures()
{
    for (auto error : {fg::StoreResult::Failed, fg::StoreResult::Corrupt}) {
        FaultStore store;
        store.read_result = error;
        fg::AuthService auth(store);
        require(auth.initialize() == fg::AuthResult::Unavailable && store.writes == 0, "read errors must never bootstrap or reset defaults");
        fg::Session output;
        require(auth.login("admin", "admin", 0, &output) == fg::AuthResult::Unavailable, "read failure must fail closed");
        require(auth.authorize("x", "x", true, true, 0) == fg::AuthResult::Unavailable, "uninitialized authorization must fail closed");
        require(auth.change_password("x", "x", kPassword, 0) == fg::AuthResult::Unavailable, "uninitialized replacement must fail closed");
        require(auth.logout("x", "x", 0) == fg::AuthResult::Unavailable, "uninitialized logout must fail closed");
    }
    FaultStore initial;
    initial.fail_write = true;
    fg::AuthService unavailable(initial);
    require(unavailable.initialize() == fg::AuthResult::Unavailable, "bootstrap commit failure must fail closed");
    fg::Session output;
    require(unavailable.login("admin", "admin", 0, &output) == fg::AuthResult::Unavailable, "unpersisted defaults must never work");

    FaultStore store;
    fg::AuthService auth(store);
    require(auth.initialize() == fg::AuthResult::Ok, "initialize");
    replace_default(auth);
    const auto session = login(auth, 1, kPassword);
    std::vector<uint8_t> before, after;
    require(store.get("admin_auth", &before) == fg::StoreResult::Ok, "record before failed change");
    store.fail_write = true;
    require(auth.change_password(session.token, session.csrf, "replacement that cannot persist", 2) == fg::AuthResult::Unavailable,
            "replacement commit failure must be reported");
    require(store.get("admin_auth", &after) == fg::StoreResult::Ok && before == after, "failed commit must preserve old record");
    require(auth.authorize(session.token, "", false, false, 3) == fg::AuthResult::Ok, "failed change must preserve sessions");
    login(auth, 4, kPassword);
    require(auth.login("admin", "replacement that cannot persist", 4, &output) == fg::AuthResult::Unauthorized, "failed replacement must not install new in-memory verifier");
    fg::AuthService recreated(store);
    require(recreated.initialize() == fg::AuthResult::Ok, "old verifier must still load");
    login(recreated, 4, kPassword);

    for (const auto& corrupt : {std::vector<uint8_t>{}, std::vector<uint8_t>{1, 0},
                                std::vector<uint8_t>(before.size() + 1, 0)}) {
        FaultStore broken;
        broken.memory.put("admin_auth", corrupt);
        fg::AuthService invalid(broken);
        require(invalid.initialize() == fg::AuthResult::Unavailable && broken.writes == 0, "malformed records must never reset defaults");
    }
    for (size_t index : {size_t{0}, size_t{1}}) {
        auto corrupt = before;
        corrupt[index] = 255;
        FaultStore broken;
        broken.memory.put("admin_auth", corrupt);
        fg::AuthService invalid(broken);
        require(invalid.initialize() == fg::AuthResult::Unavailable && broken.writes == 0, "invalid version and flag must be rejected");
    }
}

void test_crypto_failures()
{
    for (bool entropy : {true, false}) {
        FaultStore store;
        fg::AuthService auth(store);
        fail_random = entropy;
        fail_derivation = !entropy;
        require(auth.initialize() == fg::AuthResult::Unavailable && store.writes == 0, "crypto failure must not persist a default record");
        fail_random = fail_derivation = false;
        require(auth.initialize() == fg::AuthResult::Ok, "retry after crypto recovery must work");
    }
    FaultStore store;
    fg::AuthService auth(store);
    require(auth.initialize() == fg::AuthResult::Ok, "initialize");
    const auto session = login(auth);
    const size_t writes = store.writes;
    fg::Session output;
    fail_random = true;
    require(auth.login("admin", "admin", 0, &output) == fg::AuthResult::Unavailable && output.token.empty(), "session entropy failure must not mint a token");
    require(auth.change_password(session.token, session.csrf, kPassword, 0) == fg::AuthResult::Unavailable && store.writes == writes,
            "salt entropy failure must preserve verifier");
    fail_random = false;
    fail_derivation = true;
    require(auth.login("admin", "admin", 0, &output) == fg::AuthResult::Unavailable, "verification crypto failure must fail closed");
    require(auth.change_password(session.token, session.csrf, kPassword, 0) == fg::AuthResult::Unavailable && store.writes == writes,
            "replacement derivation failure must preserve verifier");
    fail_derivation = false;
    random_calls_before_failure = 1;
    require(auth.login("admin", "admin", 0, &output) == fg::AuthResult::Unavailable && output.token.empty() && output.csrf.empty(),
            "CSRF entropy failure after successful token generation must discard both secrets");
    random_calls_before_failure = -1;
    login(auth);
    login(auth);
    login(auth);
    require(auth.login("admin", "admin", 0, &output) == fg::AuthResult::RateLimited, "failed entropy attempts must not consume session slots");
    require(auth.authorize(session.token, "", false, true, 0) == fg::AuthResult::Ok, "crypto failures must preserve established session");
}
}

extern "C" int __real_RAND_bytes(unsigned char*, int);
extern "C" int __wrap_RAND_bytes(unsigned char* output, int size)
{
    if (fail_random || random_calls_before_failure == 0) return 0;
    if (random_calls_before_failure > 0) --random_calls_before_failure;
    return __real_RAND_bytes(output, size);
}

extern "C" int __real_PKCS5_PBKDF2_HMAC(const char*, int, const unsigned char*, int, int,
                                       const EVP_MD*, int, unsigned char*);
extern "C" int __wrap_PKCS5_PBKDF2_HMAC(const char* password, int password_size, const unsigned char* salt,
                                       int salt_size, int iterations, const EVP_MD* digest, int size, unsigned char* output)
{
    return fail_derivation ? 0 : __real_PKCS5_PBKDF2_HMAC(password, password_size, salt, salt_size, iterations, digest, size, output);
}

int main()
{
    test_real_crypto();
    test_default_and_persistence();
    test_csrf_logout_and_all_session_invalidation();
    test_input_and_capacity();
    test_expiry();
    test_rate_limiting();
    test_storage_failures();
    test_crypto_failures();
    return EXIT_SUCCESS;
}
