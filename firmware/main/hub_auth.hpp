#pragma once

#include <array>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>

#include "user_store.hpp"

namespace fg {

enum class HubAuthResult { Ok, Unauthorized, Malformed, Unavailable };
enum class HubCommandState : uint8_t { Reserved, Executable, Running, Granted, Rejected, Interrupted, Cancelled, Failed };
enum class HubLedgerResult { Ok, Duplicate, Full, Invalid, NotFound, Unavailable };

struct HubCommand {
    std::string request_id;
    HubCommandState state = HubCommandState::Reserved;
};

class HubCommandLedger {
public:
    explicit HubCommandLedger(KeyValueStore& storage) : storage_(storage) {}

    HubLedgerResult initialize();
    HubLedgerResult reserve(std::string_view request_id);
    HubLedgerResult mark_executable(std::string_view request_id);
    HubLedgerResult begin_execution(std::string_view request_id);
    HubLedgerResult cancel_unstarted();
    HubLedgerResult complete(std::string_view request_id, HubCommandState result);
    HubLedgerResult get(std::string_view request_id, HubCommand* command) const;

private:
    struct Persisted;
    HubLedgerResult load_locked();
    HubLedgerResult save_locked();
    int find_locked(std::string_view request_id) const;
    static bool valid_request_id(std::string_view request_id);

    KeyValueStore& storage_;
    mutable std::mutex mutex_;
    bool loaded_ = false;
    Persisted* persisted_ = nullptr;
};

class HubAuth {
public:
    explicit HubAuth(KeyValueStore& storage) : storage_(storage) {}

    HubAuthResult create_or_rotate(std::string* token);
    HubAuthResult revoke();
    HubAuthResult authorize_bearer(std::string_view header);
    HubLedgerResult begin_execution(std::string_view request_id);
    uint32_t generation() const;
    void attach_ledger(HubCommandLedger& ledger) { ledger_ = &ledger; }

private:
    HubAuthResult load_locked();
    HubAuthResult save_locked();

    KeyValueStore& storage_;
    HubCommandLedger* ledger_ = nullptr;
    mutable std::mutex mutex_;
    bool loaded_ = false;
    bool active_ = false;
    uint32_t generation_ = 0;
    std::array<uint8_t, 32> verifier_{};
};

}
