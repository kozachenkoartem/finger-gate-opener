#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "auth_crypto.hpp"
#include "user_store.hpp"

namespace fg {

enum class AuthResult { Ok, Unauthorized, Forbidden, PasswordChangeRequired, RateLimited, InvalidInput, Unavailable };

struct Session {
    std::string token;
    std::string csrf;
    bool password_change_required = false;
};

class AuthService {
public:
    explicit AuthService(KeyValueStore& storage);
    AuthResult initialize();
    AuthResult login(const std::string& username, const std::string& password, uint64_t now_ms, Session* out);
    AuthResult authorize(const std::string& token, const std::string& csrf, bool mutation,
                         bool allow_password_change, uint64_t now_ms, Session* out = nullptr);
    AuthResult change_password(const std::string& token, const std::string& csrf,
                               const std::string& new_password, uint64_t now_ms);
    AuthResult logout(const std::string& token, const std::string& csrf, uint64_t now_ms);

private:
    static constexpr auto kMaxSessions = 4;

    struct ActiveSession {
        Session session;
        uint64_t created_ms = 0;
        uint64_t last_used_ms = 0;
        bool active = false;
    };

    void expire_sessions(uint64_t now_ms);
    ActiveSession* find_session(const std::string& token);

    KeyValueStore& storage_;
    auth_crypto::Salt salt_{};
    auth_crypto::Hash hash_{};
    std::array<ActiveSession, kMaxSessions> sessions_{};
    bool initialized_ = false;
    bool password_change_required_ = true;
    uint8_t failed_logins_ = 0;
    bool locked_ = false;
    uint64_t locked_since_ms_ = 0;
};

}
