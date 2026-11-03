#include <cstdlib>
#include <iostream>

#include "audit_events.hpp"
#include "user_store.hpp"

namespace {

void require(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}

fg::User user(uint16_t slot, const char* name)
{
    fg::User value;
    value.slot = slot;
    value.name = name;
    return value;
}

void test_pending_add_is_quarantined_until_committed()
{
    fg::MemoryKeyValueStore storage;
    fg::UserStore store(storage);
    require(store.stage(user(1, "\xD0\x98\xD0\xBC\xD1\x8F")) == fg::StoreResult::Ok, "stage must persist intent");

    const fg::StoreSnapshot interrupted = store.load();
    require(interrupted.quarantined.test(1), "interrupted add slot must be quarantined");
    require(interrupted.registry.access_decision(1) == fg::AccessDecision::DenyUnknown,
            "interrupted add must not grant access");

    require(store.commit(1) == fg::StoreResult::Ok, "commit must finalize stored template metadata");
    const fg::StoreSnapshot loaded = store.load();
    require(!loaded.quarantined.test(1), "committed slot must not remain quarantined");
    require(loaded.registry.access_decision(1) == fg::AccessDecision::Grant,
            "committed active record must grant access");
    require(loaded.registry.find(1)->name == "\xD0\x98\xD0\xBC\xD1\x8F", "UTF-8 name must round-trip");
}

void test_pending_delete_is_quarantined_and_commit_revokes_access()
{
    fg::MemoryKeyValueStore storage;
    fg::UserStore store(storage);
    require(store.stage(user(2, "Alice")) == fg::StoreResult::Ok, "stage add must succeed");
    require(store.commit(2) == fg::StoreResult::Ok, "commit add must succeed");
    require(store.stage_delete(2) == fg::StoreResult::Ok, "delete intent must persist before sensor deletion");

    const fg::StoreSnapshot interrupted = store.load();
    require(interrupted.quarantined.test(2), "uncertain delete must quarantine slot");
    require(interrupted.registry.access_decision(2) == fg::AccessDecision::DenyUnknown,
            "uncertain delete must fail closed");
    require(store.commit_delete(2) == fg::StoreResult::Ok, "confirmed deletion must remove metadata");
    require(store.load().registry.access_decision(2) == fg::AccessDecision::DenyUnknown,
            "deleted record must remain denied");
}

void test_malformed_record_quarantines_only_affected_slot()
{
    fg::MemoryKeyValueStore storage;
    fg::UserStore store(storage);
    require(store.stage(user(3, "Safe")) == fg::StoreResult::Ok, "stage safe user must succeed");
    require(store.commit(3) == fg::StoreResult::Ok, "commit safe user must succeed");
    storage.put("u4", {0xFF});

    const fg::StoreSnapshot loaded = store.load();
    require(loaded.quarantined.test(4), "malformed slot must be quarantined");
    require(loaded.registry.access_decision(3) == fg::AccessDecision::Grant,
            "unaffected slots must remain usable");
}

void test_audit_queue_drops_when_full()
{
    fg::AuditEventSink events(2);
    require(events.publish({fg::AuditEventType::Recognition, 1}), "first event must enqueue");
    require(events.publish({fg::AuditEventType::Recognition, 2}), "second event must enqueue");
    require(!events.publish({fg::AuditEventType::Recognition, 3}), "full queue must reject event without blocking");
    require(events.dropped_count() == 1, "dropped event count must be retained");
}

}

int main()
{
    test_pending_add_is_quarantined_until_committed();
    test_pending_delete_is_quarantined_and_commit_revokes_access();
    test_malformed_record_quarantines_only_affected_slot();
    test_audit_queue_drops_when_full();
    return EXIT_SUCCESS;
}
