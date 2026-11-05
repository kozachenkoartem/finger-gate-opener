#include "hub_auth.hpp"

#include <array>
#include <cstring>
#include <cstdlib>
#include <iostream>

namespace {
void require(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}
}

int main()
{
    fg::MemoryKeyValueStore storage;
    fg::HubAuth auth(storage);
    std::string first;
    require(auth.create_or_rotate(&first) == fg::HubAuthResult::Ok, "new hub token issued");
    require(first.size() == 64, "token is 32 bytes of lowercase hex");
    require(auth.authorize_bearer("Bearer " + first) == fg::HubAuthResult::Ok, "issued token authorizes");
    require(auth.authorize_bearer(first) == fg::HubAuthResult::Malformed, "bare token is rejected");
    require(auth.authorize_bearer("Bearer " + first + " ") == fg::HubAuthResult::Malformed, "non-canonical bearer is rejected");

    std::string second;
    require(auth.create_or_rotate(&second) == fg::HubAuthResult::Ok, "token rotates");
    require(second != first, "rotation creates a distinct token");
    require(auth.authorize_bearer("Bearer " + first) == fg::HubAuthResult::Unauthorized, "rotated token is rejected");
    require(auth.authorize_bearer("Bearer " + second) == fg::HubAuthResult::Ok, "replacement token authorizes");
    require(auth.revoke() == fg::HubAuthResult::Ok, "token revokes");
    require(auth.authorize_bearer("Bearer " + second) == fg::HubAuthResult::Unauthorized, "revoked token is rejected");
    require(auth.create_or_rotate(&second) == fg::HubAuthResult::Ok, "token restores for rate-limit test");
    for (unsigned attempt = 0; attempt < 5; ++attempt)
        require(auth.authorize_bearer("Bearer " + std::string(64, '0'), 1000) == fg::HubAuthResult::Unauthorized,
                "bounded invalid token attempts are rejected");
    require(auth.authorize_bearer("Bearer " + std::string(64, '0'), 1000) == fg::HubAuthResult::RateLimited,
            "excess invalid token attempts are rate limited");
    require(auth.authorize_bearer("Bearer " + second, 1000) == fg::HubAuthResult::Ok,
            "valid token clears failed authorization rate limiting");

    fg::HubCommandLedger ledger(storage);
    require(ledger.initialize() == fg::HubLedgerResult::Ok, "ledger initializes");
    require(ledger.reserve("0123456789abcdef") == fg::HubLedgerResult::Ok, "command intent persists");
    require(ledger.reserve("0123456789abcdef") == fg::HubLedgerResult::Duplicate, "duplicate intent is idempotent");
    require(ledger.mark_executable("0123456789abcdef") == fg::HubLedgerResult::Ok, "intent becomes executable");
    require(ledger.begin_execution("0123456789abcdef") == fg::HubLedgerResult::Ok, "execution starts once");
    require(ledger.begin_execution("0123456789abcdef") == fg::HubLedgerResult::Duplicate, "execution cannot start twice");
    require(ledger.complete("0123456789abcdef", fg::HubCommandState::Granted) == fg::HubLedgerResult::Ok, "terminal result persists");

    require(ledger.reserve("fedcba9876543210") == fg::HubLedgerResult::Ok, "second command intent persists");
    require(ledger.mark_executable("fedcba9876543210") == fg::HubLedgerResult::Ok, "second command is queued");
    auth.attach_ledger(ledger);
    require(auth.create_or_rotate(&second) == fg::HubAuthResult::Ok, "rotation replaces token");
    fg::HubCommand pending;
    require(ledger.get("fedcba9876543210", &pending) == fg::HubLedgerResult::Ok &&
            pending.state == fg::HubCommandState::Cancelled,
            "rotation cancels unstarted commands");

    require(ledger.reserve("short") == fg::HubLedgerResult::Invalid, "invalid request id rejected");
    require(ledger.reserve("0123456789abcdee") == fg::HubLedgerResult::Ok, "pre-execution failure fixture reserves");
    require(ledger.complete("0123456789abcdee", fg::HubCommandState::Failed) == fg::HubLedgerResult::Ok,
            "failed acceptance becomes terminal before execution");

    fg::MemoryKeyValueStore eviction_storage;
    fg::HubCommandLedger eviction_ledger(eviction_storage);
    for (unsigned index = 0; index < 16; ++index) {
        const std::string request_id = "00000000000000" + std::to_string(10 + index);
        require(eviction_ledger.reserve(request_id) == fg::HubLedgerResult::Ok, "terminal eviction fixture reserves");
        require(eviction_ledger.complete(request_id, fg::HubCommandState::Failed) == fg::HubLedgerResult::Ok, "terminal eviction fixture fails");
    }
    require(eviction_ledger.reserve("0000000000000099") == fg::HubLedgerResult::Ok, "oldest terminal entry is evicted");
    fg::HubCommand evicted;
    require(eviction_ledger.get("0000000000000010", &evicted) == fg::HubLedgerResult::NotFound,
            "ledger evicts the oldest terminal command");

    struct LegacyLedgerEntry {
        std::array<char, 65> request_id{};
        fg::HubCommandState state = fg::HubCommandState::Reserved;
    };
    struct LegacyLedger {
        uint32_t magic = 0x46474c47;
        uint16_t version = 1;
        uint16_t reserved = 0;
        std::array<LegacyLedgerEntry, 16> entries{};
    } legacy;
    std::memcpy(legacy.entries[0].request_id.data(), "legacy-id-000001", 16);
    legacy.entries[0].state = fg::HubCommandState::Granted;
    fg::MemoryKeyValueStore legacy_storage;
    const auto* raw = reinterpret_cast<const uint8_t*>(&legacy);
    require(legacy_storage.put("hub_ledger", std::vector<uint8_t>(raw, raw + sizeof(legacy))) == fg::StoreResult::Ok,
            "legacy ledger fixture persists");
    fg::HubCommandLedger migrated_ledger(legacy_storage);
    require(migrated_ledger.initialize() == fg::HubLedgerResult::Ok, "version-one ledger migrates");
    fg::HubCommand migrated;
    require(migrated_ledger.get("legacy-id-000001", &migrated) == fg::HubLedgerResult::Ok &&
                migrated.state == fg::HubCommandState::Granted,
            "migration retains terminal command state");
    return EXIT_SUCCESS;
}
