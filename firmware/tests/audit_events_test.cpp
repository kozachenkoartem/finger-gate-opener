#include "audit_events.hpp"

#include <cstdlib>
#include <iostream>

namespace {
using namespace fg;

void require(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}

void test_publisher_persists_queued_events_and_drops_without_blocking()
{
    MemoryAuditStorage storage;
    AuditStore store(storage);
    require(store.initialize() == AuditResult::Ok, "initialize audit store");
    AuditPublisher publisher(store, 1);

    AuditRecord first;
    first.type = AuditType::Access;
    first.result = AuditResultCode::Granted;
    first.source = AuditSource::Fingerprint;
    first.slot = 7;
    require(publisher.publish(first), "first event must enter queue");
    require(!publisher.publish(first), "full queue must reject without storage I/O");
    require(publisher.dropped_count() == 1, "full queue must count dropped events");
    require(publisher.drain(1) == 1, "storage owner must persist queued event");

    AuditPage page;
    require(store.read_after({}, 8, &page) == AuditResult::Ok, "read persisted event");
    require(page.events.size() == 1, "one queued event persisted");
    require(page.events[0].slot == 7 && page.events[0].type == AuditType::Access,
            "persisted event fields");
}

void test_publisher_counts_store_failure_without_rejecting_local_producer()
{
    MemoryAuditStorage storage;
    AuditStore store(storage);
    require(store.initialize() == AuditResult::Ok, "initialize audit store");
    AuditPublisher publisher(store, 2);
    storage.fail_next_append();

    require(publisher.publish({}), "producer must accept event before deferred store failure");
    require(publisher.drain(1) == 0, "failed append must not be reported as persisted");
    require(publisher.failed_count() == 1, "failed append must be counted");
}
}

int main()
{
    test_publisher_persists_queued_events_and_drops_without_blocking();
    test_publisher_counts_store_failure_without_rejecting_local_producer();
    return EXIT_SUCCESS;
}
