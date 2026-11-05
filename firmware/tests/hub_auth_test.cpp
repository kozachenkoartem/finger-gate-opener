#include "hub_auth.hpp"

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
    return EXIT_SUCCESS;
}
