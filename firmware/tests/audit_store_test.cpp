#include "audit_store.hpp"

#include <cstdlib>
#include <iostream>

namespace {
void require(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

void test_empty_store_accepts_first_event()
{
    fg::MemoryAuditStorage storage;
    fg::AuditStore audit(storage);
    require(audit.initialize() == fg::AuditResult::Ok, "empty store initializes");

    fg::AuditRecord event{};
    event.type = fg::AuditType::Access;
    event.result = fg::AuditResultCode::Granted;
    event.source = fg::AuditSource::Fingerprint;
    event.slot = 7;
    event.elapsed_ms = 42;
    require(audit.append(event) == fg::AuditResult::Ok, "first event commits");

    fg::AuditPage page;
    require(audit.read_after({}, 1, &page) == fg::AuditResult::Ok, "first page reads");
    require(page.events.size() == 1 && page.events.front().slot == 7, "stored event is returned");
}

void test_rotation_preserves_latest_512_events()
{
    fg::MemoryAuditStorage storage;
    fg::AuditStore audit(storage);
    require(audit.initialize() == fg::AuditResult::Ok, "store initializes before rotation");
    for (uint64_t sequence = 1; sequence <= 513; ++sequence) {
        fg::AuditRecord event{};
        event.elapsed_ms = sequence;
        require(audit.append(event) == fg::AuditResult::Ok, "event commits before rotation");
    }
    fg::AuditPage page;
    require(audit.read_after({}, 512, &page) == fg::AuditResult::Ok, "rotation page reads");
    require(page.events.size() == 512, "rotation retains exactly 512 events");
    require(page.events.front().elapsed_ms == 2 && page.events.back().elapsed_ms == 513,
            "rotation drops only the oldest event");
}

void test_reboot_preserves_committed_events()
{
    fg::MemoryAuditStorage storage;
    {
        fg::AuditStore audit(storage);
        require(audit.initialize() == fg::AuditResult::Ok, "first boot initializes");
        fg::AuditRecord event{};
        event.elapsed_ms = 99;
        require(audit.append(event) == fg::AuditResult::Ok, "event commits before reboot");
    }
    fg::AuditStore rebooted(storage);
    require(rebooted.initialize() == fg::AuditResult::Ok, "reboot initializes");
    fg::AuditPage page;
    require(rebooted.read_after({}, 1, &page) == fg::AuditResult::Ok && page.events.size() == 1,
            "reboot reads committed event");
    require(page.events.front().elapsed_ms == 99, "reboot preserves event data");
}

void test_clear_invalidates_old_cursor()
{
    fg::MemoryAuditStorage storage;
    fg::AuditStore audit(storage);
    require(audit.initialize() == fg::AuditResult::Ok, "store initializes before clear");
    fg::AuditRecord event{};
    require(audit.append(event) == fg::AuditResult::Ok, "event commits before clear");
    fg::AuditPage before;
    require(audit.read_after({}, 1, &before) == fg::AuditResult::Ok, "cursor source reads");
    require(audit.clear() == fg::AuditResult::Ok, "clear commits");
    fg::AuditPage after;
    require(audit.read_after(before.events.front().id, 1, &after) == fg::AuditResult::Invalid,
            "old cursor is rejected after clear");
}

void test_future_cursor_is_rejected()
{
    fg::MemoryAuditStorage storage;
    fg::AuditStore audit(storage);
    require(audit.initialize() == fg::AuditResult::Ok, "store initializes before future cursor");
    fg::AuditRecord event{};
    require(audit.append(event) == fg::AuditResult::Ok, "event commits before future cursor");
    fg::AuditPage page;
    require(audit.read_after({1, 2}, 1, &page) == fg::AuditResult::Invalid,
            "future cursor cannot hide events");
}

void test_failed_append_is_not_visible_after_reboot()
{
    fg::MemoryAuditStorage storage;
    fg::AuditStore audit(storage);
    require(audit.initialize() == fg::AuditResult::Ok, "store initializes before write fault");
    storage.fail_next_append();
    fg::AuditRecord event{};
    require(audit.append(event) == fg::AuditResult::Unavailable, "write fault rejects event");
    fg::AuditStore rebooted(storage);
    require(rebooted.initialize() == fg::AuditResult::Ok, "reboot after failed write initializes");
    fg::AuditPage page;
    require(rebooted.read_after({}, 1, &page) == fg::AuditResult::Ok && page.events.empty(),
            "failed append is absent after reboot");
}

void test_page_returns_next_cursor()
{
    fg::MemoryAuditStorage storage;
    fg::AuditStore audit(storage);
    require(audit.initialize() == fg::AuditResult::Ok, "store initializes before pagination");
    for (uint64_t value = 1; value <= 3; ++value) {
        fg::AuditRecord event{};
        event.elapsed_ms = value;
        require(audit.append(event) == fg::AuditResult::Ok, "pagination fixture commits");
    }
    fg::AuditPage first;
    require(audit.read_after({}, 2, &first) == fg::AuditResult::Ok, "first page reads");
    require(first.has_more && first.next_after.sequence == 2, "first page exposes continuation");
    fg::AuditPage second;
    require(audit.read_after(first.next_after, 2, &second) == fg::AuditResult::Ok, "second page reads");
    require(second.events.size() == 1 && !second.has_more && second.events.front().elapsed_ms == 3,
            "continuation returns remaining event");
}

void test_store_uses_raw_storage_interface()
{
    fg::MemoryAuditStorage storage;
    fg::AuditStorage& raw = storage;
    fg::AuditStore audit(raw);
    require(audit.initialize() == fg::AuditResult::Ok, "store initializes through raw storage interface");
}

void test_storage_commit_failure_does_not_publish_event()
{
    fg::MemoryAuditStorage storage;
    fg::AuditStorage& raw = storage;
    fg::AuditStore audit(raw);
    require(audit.initialize() == fg::AuditResult::Ok, "store initializes before durable failure");
    storage.fail_next_commit();
    fg::AuditRecord event{};
    require(audit.append(event) == fg::AuditResult::Unavailable, "durable commit failure is returned");
    fg::AuditPage page;
    require(audit.read_after({}, 1, &page) == fg::AuditResult::Ok && page.events.empty(),
            "uncommitted event is not published");
}

void test_recovery_ignores_torn_and_corrupt_records_without_reusing_ids()
{
    fg::MemoryAuditStorage storage;
    fg::AuditStore audit(storage);
    require(audit.initialize() == fg::AuditResult::Ok, "store initializes before recovery fixture");

    fg::AuditRecord first{};
    first.elapsed_ms = 1;
    require(audit.append(first) == fg::AuditResult::Ok, "first recovery fixture commits");

    storage.fail_after_write_bytes(100);
    fg::AuditRecord torn{};
    torn.elapsed_ms = 2;
    require(audit.append(torn) == fg::AuditResult::Unavailable, "torn record reports unavailable");

    fg::AuditStore rebooted(storage);
    require(rebooted.initialize() == fg::AuditResult::Ok, "reboot recovers torn record");
    fg::AuditRecord replacement{};
    replacement.elapsed_ms = 3;
    require(rebooted.append(replacement) == fg::AuditResult::Ok, "append after torn record succeeds");

    fg::AuditPage page;
    require(rebooted.read_after({}, 8, &page) == fg::AuditResult::Ok, "recovered page reads");
    require(page.events.size() == 2 && page.events[0].elapsed_ms == 1 && page.events[1].elapsed_ms == 3,
            "torn record is not returned");
    require(page.events[1].id.sequence > page.events[0].id.sequence + 1,
            "reserved sequence is not reused after torn record");

    storage.corrupt_byte(fg::AuditStore::kDataOffset + fg::AuditStore::kRecordSize - 1);
    fg::AuditStore after_corruption(storage);
    require(after_corruption.initialize() == fg::AuditResult::Ok, "reboot ignores bad CRC");
    require(after_corruption.read_after({}, 8, &page) == fg::AuditResult::Ok && page.events.size() == 1,
            "bad CRC record is not returned");
}

void test_interrupted_rotation_recovers_before_the_next_append()
{
    fg::MemoryAuditStorage complete;
    fg::AuditStore seed(complete);
    require(seed.initialize() == fg::AuditResult::Ok, "rotation seed initializes");
    for (uint64_t value = 1; value <= 512; ++value) {
        fg::AuditRecord event{};
        event.elapsed_ms = value;
        require(seed.append(event) == fg::AuditResult::Ok, "rotation seed commits");
    }
    fg::AuditRecord first_rotation{};
    first_rotation.elapsed_ms = 513;
    require(seed.append(first_rotation) == fg::AuditResult::Ok, "rotation seed creates a spare sector");

    for (size_t bytes : {size_t{0}, size_t{512}, size_t{3584}}) {
        fg::MemoryAuditStorage storage = complete;
        fg::AuditStore interrupted(storage);
        require(interrupted.initialize() == fg::AuditResult::Ok, "interrupted rotation initializes");
        storage.fail_after_write_bytes(bytes);
        fg::AuditRecord event{};
        event.elapsed_ms = 514;
        require(interrupted.append(event) == fg::AuditResult::Unavailable, "rotation write interruption is reported");

        fg::AuditStore rebooted(storage);
        require(rebooted.initialize() == fg::AuditResult::Ok, "interrupted rotation reboots");
        event.elapsed_ms = 515;
        require(rebooted.append(event) == fg::AuditResult::Ok, "append completes after interrupted rotation");
        fg::AuditPage page;
        require(rebooted.read_after({}, 512, &page) == fg::AuditResult::Ok && page.events.size() == 512,
                "interrupted rotation retains a full recoverable journal");
    }

    fg::MemoryAuditStorage storage = complete;
    fg::AuditStore interrupted(storage);
    require(interrupted.initialize() == fg::AuditResult::Ok, "erase interruption initializes");
    storage.fail_next_erase();
    fg::AuditRecord event{};
    event.elapsed_ms = 514;
    require(interrupted.append(event) == fg::AuditResult::Unavailable, "rotation erase interruption is reported");
    fg::AuditStore rebooted(storage);
    require(rebooted.initialize() == fg::AuditResult::Ok, "erase interruption reboots");
    event.elapsed_ms = 515;
    require(rebooted.append(event) == fg::AuditResult::Ok, "append completes after erase interruption");
}

void test_stale_unformatted_audit_partition_is_reinitialized()
{
    fg::MemoryAuditStorage storage;
    fg::AuditStore first(storage);
    require(first.initialize() == fg::AuditResult::Ok, "first store initializes");
    fg::AuditRecord event{};
    require(first.append(event) == fg::AuditResult::Ok, "stale-format fixture commits");
    storage.corrupt_byte(0);
    fg::AuditStore migrated(storage);
    require(migrated.initialize() == fg::AuditResult::Ok, "unknown old audit format is reinitialized");
    fg::AuditPage page;
    require(migrated.read_after({}, 1, &page) == fg::AuditResult::Ok && page.events.empty(),
            "stale records are not exposed after reinitialization");
}

void test_interrupted_clear_completes_on_reboot_in_a_new_epoch()
{
    fg::MemoryAuditStorage storage;
    fg::AuditStore audit(storage);
    require(audit.initialize() == fg::AuditResult::Ok, "clear fixture initializes");
    fg::AuditRecord before{};
    before.elapsed_ms = 1;
    require(audit.append(before) == fg::AuditResult::Ok, "clear fixture commits");
    fg::AuditPage page;
    require(audit.read_after({}, 1, &page) == fg::AuditResult::Ok, "clear fixture reads old cursor");
    const fg::AuditCursor old_cursor = page.next_after;

    storage.fail_after_erase_operations(1);
    require(audit.clear() == fg::AuditResult::Unavailable, "interrupted clear reports unavailable");
    fg::AuditStore rebooted(storage);
    require(rebooted.initialize() == fg::AuditResult::Ok, "reboot completes interrupted clear");
    require(rebooted.read_after(old_cursor, 1, &page) == fg::AuditResult::Invalid,
            "old epoch cursor remains invalid after recovery");
    fg::AuditRecord after{};
    after.elapsed_ms = 2;
    require(rebooted.append(after) == fg::AuditResult::Ok, "append succeeds after clear recovery");
    require(rebooted.read_after({}, 1, &page) == fg::AuditResult::Ok && page.events.front().id.epoch != old_cursor.epoch &&
                page.events.front().id.sequence > old_cursor.sequence,
            "new epoch preserves reserved sequence high-water");
}

}

int main()
{
    test_empty_store_accepts_first_event();
    test_rotation_preserves_latest_512_events();
    test_reboot_preserves_committed_events();
    test_clear_invalidates_old_cursor();
    test_future_cursor_is_rejected();
    test_failed_append_is_not_visible_after_reboot();
    test_page_returns_next_cursor();
    test_store_uses_raw_storage_interface();
    test_storage_commit_failure_does_not_publish_event();
    test_recovery_ignores_torn_and_corrupt_records_without_reusing_ids();
    test_interrupted_rotation_recovers_before_the_next_append();
    test_stale_unformatted_audit_partition_is_reinitialized();
    test_interrupted_clear_completes_on_reboot_in_a_new_epoch();
    std::cout << "Audit store: PASS\n";
}
