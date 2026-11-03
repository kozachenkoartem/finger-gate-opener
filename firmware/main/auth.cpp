#include "auth.hpp"

#include <algorithm>
#include <vector>

namespace fg {
namespace {
constexpr char kRecordKey[] = "admin_auth";
constexpr char kAdmin[] = "admin";
constexpr uint8_t kRecordVersion = 1;
constexpr size_t kHeaderSize = 2;
constexpr size_t kRecordSize = kHeaderSize + auth_crypto::kSaltSize + auth_crypto::kHashSize;
constexpr size_t kMinPasswordSize = 12;
constexpr size_t kMaxInputSize = 128;
constexpr size_t kSecretHexSize = auth_crypto::kSecretSize * 2;
constexpr uint64_t kIdleTimeoutMs = 15 * 60 * 1000;
constexpr uint64_t kAbsoluteTimeoutMs = 8 * 60 * 60 * 1000;
constexpr uint64_t kLockDurationMs = 60 * 1000;
constexpr uint8_t kMaxFailedLogins = 5;

struct Verifier {
    auth_crypto::Salt salt{};
    auth_crypto::Hash hash{};

    ~Verifier() { auth_crypto::wipe(hash.data(), hash.size()); }
};

bool valid_input(const std::string& value, size_t minimum = 1)
{
    return value.size() >= minimum && value.size() <= kMaxInputSize && value.find('\0') == std::string::npos;
}

bool equal_text(const std::string& left, const std::string& right)
{
    return left.size() == right.size() && auth_crypto::constant_time_equal(
        reinterpret_cast<const uint8_t*>(left.data()), reinterpret_cast<const uint8_t*>(right.data()), left.size());
}

std::vector<uint8_t> encode(const Verifier& verifier, bool must_change)
{
    // Версия 1 фиксирует PBKDF2-HMAC-SHA256, 60000 итераций, соль 16 и хеш 32 байта.
    std::vector<uint8_t> bytes{kRecordVersion, static_cast<uint8_t>(must_change)};
    bytes.insert(bytes.end(), verifier.salt.begin(), verifier.salt.end());
    bytes.insert(bytes.end(), verifier.hash.begin(), verifier.hash.end());
    return bytes;
}

bool decode(const std::vector<uint8_t>& bytes, Verifier* verifier, bool* must_change)
{
    if (bytes.size() != kRecordSize || bytes[0] != kRecordVersion || bytes[1] > 1) return false;
    std::copy_n(bytes.begin() + kHeaderSize, verifier->salt.size(), verifier->salt.begin());
    std::copy_n(bytes.begin() + kHeaderSize + verifier->salt.size(), verifier->hash.size(), verifier->hash.begin());
    *must_change = bytes[1] != 0;
    return true;
}

bool create_verifier(const std::string& password, Verifier* verifier)
{
    return auth_crypto::random_bytes(verifier->salt.data(), verifier->salt.size()) &&
           auth_crypto::derive_password(password, verifier->salt, &verifier->hash);
}

void clear_session(Session* session)
{
    auth_crypto::wipe(reinterpret_cast<uint8_t*>(session->token.data()), session->token.size());
    auth_crypto::wipe(reinterpret_cast<uint8_t*>(session->csrf.data()), session->csrf.size());
    *session = {};
}
}

AuthService::AuthService(KeyValueStore& storage) : storage_(storage) {}

AuthResult AuthService::initialize()
{
    if (initialized_) return AuthResult::Ok;
    std::vector<uint8_t> bytes;
    const StoreResult result = storage_.get(kRecordKey, &bytes);
    Verifier verifier;
    bool must_change = true;
    if (result == StoreResult::NotFound) {
        if (!create_verifier(kAdmin, &verifier) || storage_.put(kRecordKey, encode(verifier, true)) != StoreResult::Ok) {
            return AuthResult::Unavailable;
        }
    } else if (result != StoreResult::Ok || !decode(bytes, &verifier, &must_change)) {
        return AuthResult::Unavailable;
    }
    salt_ = verifier.salt;
    hash_ = verifier.hash;
    password_change_required_ = must_change;
    initialized_ = true;
    return AuthResult::Ok;
}

void AuthService::expire_sessions(uint64_t now_ms)
{
    for (auto& slot : sessions_) {
        if (slot.active && (now_ms < slot.last_used_ms || now_ms < slot.created_ms ||
                            now_ms - slot.last_used_ms >= kIdleTimeoutMs ||
                            now_ms - slot.created_ms >= kAbsoluteTimeoutMs)) {
            clear_session(&slot.session);
            slot = {};
        }
    }
}

AuthService::ActiveSession* AuthService::find_session(const std::string& token)
{
    if (token.size() != kSecretHexSize) return nullptr;
    ActiveSession* match = nullptr;
    for (auto& slot : sessions_) {
        if (slot.active && equal_text(token, slot.session.token)) match = &slot;
    }
    return match;
}

AuthResult AuthService::login(const std::string& username, const std::string& password, uint64_t now_ms, Session* out)
{
    const auto fail = [out](AuthResult result) {
        if (out != nullptr) clear_session(out);
        return result;
    };
    if (!initialized_) return fail(AuthResult::Unavailable);
    if (out == nullptr) return AuthResult::InvalidInput;
    if (locked_) {
        if (now_ms < locked_since_ms_ || now_ms - locked_since_ms_ < kLockDurationMs) return fail(AuthResult::RateLimited);
        locked_ = false;
        failed_logins_ = 0;
    }
    if (!valid_input(username) || !valid_input(password)) return fail(AuthResult::InvalidInput);

    Verifier candidate;
    // Неизвестное имя проходит ту же дорогую проверку пароля и общий счётчик ошибок.
    if (!auth_crypto::derive_password(password, salt_, &candidate.hash)) return fail(AuthResult::Unavailable);
    const bool password_matches = auth_crypto::constant_time_equal(candidate.hash.data(), hash_.data(), hash_.size());
    const bool username_matches = equal_text(username, kAdmin);
    if (!password_matches || !username_matches) {
        if (++failed_logins_ >= kMaxFailedLogins) {
            locked_ = true;
            locked_since_ms_ = now_ms;
            return fail(AuthResult::RateLimited);
        }
        return fail(AuthResult::Unauthorized);
    }
    failed_logins_ = 0;
    expire_sessions(now_ms);
    auto free_slot = std::find_if(sessions_.begin(), sessions_.end(), [](const ActiveSession& slot) { return !slot.active; });
    if (free_slot == sessions_.end()) return fail(AuthResult::RateLimited);
    Session session;
    if (!auth_crypto::random_secret(&session.token) || !auth_crypto::random_secret(&session.csrf)) {
        clear_session(&session);
        return fail(AuthResult::Unavailable);
    }
    session.password_change_required = password_change_required_;
    *free_slot = {session, now_ms, now_ms, true};
    *out = session;
    clear_session(&session);
    return AuthResult::Ok;
}

AuthResult AuthService::authorize(const std::string& token, const std::string& csrf, bool mutation,
                                  bool allow_password_change, uint64_t now_ms, Session* out)
{
    const auto fail = [out](AuthResult result) {
        if (out != nullptr) clear_session(out);
        return result;
    };
    if (!initialized_) return fail(AuthResult::Unavailable);
    expire_sessions(now_ms);
    ActiveSession* slot = find_session(token);
    if (slot == nullptr) return fail(AuthResult::Unauthorized);
    if (mutation && !equal_text(csrf, slot->session.csrf)) return fail(AuthResult::Forbidden);
    if (slot->session.password_change_required && !allow_password_change) return fail(AuthResult::PasswordChangeRequired);
    slot->last_used_ms = now_ms;
    if (out != nullptr) *out = slot->session;
    return AuthResult::Ok;
}

AuthResult AuthService::change_password(const std::string& token, const std::string& csrf,
                                       const std::string& new_password, uint64_t now_ms)
{
    const AuthResult access = authorize(token, csrf, true, true, now_ms);
    if (access != AuthResult::Ok) return access;
    if (!valid_input(new_password, kMinPasswordSize) || equal_text(new_password, kAdmin)) return AuthResult::InvalidInput;
    Verifier replacement;
    if (!create_verifier(new_password, &replacement)) return AuthResult::Unavailable;
    // Сначала подтверждаем запись; ошибка не меняет действующий проверочный хеш и сессии.
    if (storage_.put(kRecordKey, encode(replacement, false)) != StoreResult::Ok) return AuthResult::Unavailable;
    salt_ = replacement.salt;
    hash_ = replacement.hash;
    password_change_required_ = false;
    for (auto& slot : sessions_) {
        clear_session(&slot.session);
        slot = {};
    }
    return AuthResult::Ok;
}

AuthResult AuthService::logout(const std::string& token, const std::string& csrf, uint64_t now_ms)
{
    const AuthResult access = authorize(token, csrf, true, true, now_ms);
    if (access != AuthResult::Ok) return access;
    ActiveSession* slot = find_session(token);
    clear_session(&slot->session);
    *slot = {};
    return AuthResult::Ok;
}

}
