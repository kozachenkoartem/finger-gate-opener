#include "fingerprint_controller.hpp"
#include "audit_events.hpp"

#include <cstdlib>
#include <deque>
#include <functional>
#include <iostream>
#include <memory>
#include <utility>

namespace {
using namespace fg;
const char* current_test = "";

void require(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << current_test << ": " << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}

struct Clock final : FingerprintClock {
    uint64_t now = 0;
    uint64_t now_ms() const override { return now; }
};

struct Storage final : KeyValueStore {
    struct Fault {
        std::string operation;
        std::string key;
        bool ambiguous;
        unsigned skip;
    };
    MemoryKeyValueStore memory;
    std::deque<Fault> faults;
    bool write_then_fail = false;
    bool unavailable = false;
    std::function<void(const std::string&, const std::string&)> before_operation;
    unsigned writes = 0;

    void fail(std::string operation, std::string key, bool ambiguous = false, unsigned skip = 0)
    {
        faults.push_back({std::move(operation), std::move(key), ambiguous, skip});
    }
    bool fault(const std::string& operation, const std::string& key)
    {
        if (before_operation) before_operation(operation, key);
        write_then_fail = false;
        if (unavailable) return true;
        for (auto item = faults.begin(); item != faults.end(); ++item) {
            if (operation != item->operation || key != item->key) continue;
            if (item->skip) { --item->skip; return false; }
            write_then_fail = item->ambiguous;
            faults.erase(item);
            return true;
        }
        return false;
    }
    StoreResult get(const std::string& key, std::vector<uint8_t>* value) const override
    {
        const auto result = memory.get(key, value);
        if (const_cast<Storage*>(this)->fault("get", key)) return StoreResult::Failed;
        return result;
    }
    StoreResult put(const std::string& key, const std::vector<uint8_t>& value) override
    {
        ++writes;
        if (!fault("put", key)) return memory.put(key, value);
        if (write_then_fail) memory.put(key, value);
        return StoreResult::Failed;
    }
    StoreResult erase(const std::string& key) override
    {
        ++writes;
        if (!fault("erase", key)) return memory.erase(key);
        if (write_then_fail) memory.erase(key);
        return StoreResult::Failed;
    }
};

struct Gate final : FingerprintGate {
    Clock& clock;
    unsigned calls = 0;
    bool accept = true;
    uint64_t timestamp_offset = 0;
    explicit Gate(Clock& clock) : clock(clock) {}
    PulseResult pulse() override { ++calls; return {accept, clock.now + timestamp_offset}; }
};

struct Step {
    std::string operation;
    SensorCode code = SensorCode::Ok;
    uint16_t slot = 0;
    uint8_t buffer = 0;
    std::bitset<UserRegistry::kSlotCount> occupied;
    uint32_t elapsed = 0;
    uint32_t expected_timeout = 0;
};

struct Sensor final : FingerprintSensor {
    Storage& storage;
    Clock& clock;
    std::deque<Step> steps;
    std::vector<Step> calls;
    explicit Sensor(Storage& storage, Clock& clock) : storage(storage), clock(clock) {}

    void expect(const std::string& operation, SensorCode code = SensorCode::Ok,
                uint8_t buffer = 0, uint16_t slot = 0)
    {
        steps.push_back({operation, code, slot, buffer, {}, 0, 0});
    }
    void expect_index(std::bitset<UserRegistry::kSlotCount> occupied = {}, SensorCode code = SensorCode::Ok)
    {
        expect("index", code);
        steps.back().occupied = occupied;
    }
    SensorReply run(const std::string& operation, uint8_t buffer, uint16_t slot, uint32_t timeout)
    {
        require(!steps.empty(), "unexpected sensor transaction");
        auto step = steps.front();
        steps.pop_front();
        if (step.operation != operation) {
            std::cerr << "expected " << step.operation << ", got " << operation << '\n';
            require(false, "sensor transaction ordering");
        }
        require(step.buffer == buffer, "wrong template buffer");
        if (operation == "store" || operation == "erase") require(step.slot == slot, "wrong mutation slot");
        const auto maximum = operation == "search" ? 750U :
                             operation == "store" || operation == "erase" ? 500U : 300U;
        require(timeout > 0 && timeout <= maximum, "unbounded sensor wait");
        if (step.expected_timeout) require(timeout == step.expected_timeout, "deadline budget was not propagated");
        if (operation == "store")
            require(UserStore(storage).load().pending_add.test(slot), "sensor store before persisted intent");
        if (operation == "erase") {
            const auto persisted = UserStore(storage).load();
            require(persisted.pending_add.test(slot) || persisted.pending_delete.test(slot) || persisted.quarantined.test(slot),
                    "sensor erase without persisted operation intent");
        }
        calls.push_back(step);
        clock.now += step.elapsed;
        return {step.code, step.slot, step.occupied};
    }
    SensorReply capture(uint32_t timeout) override { return run("capture", 0, 0, timeout); }
    SensorReply convert(uint8_t buffer, uint32_t timeout) override { return run("convert", buffer, 0, timeout); }
    SensorReply search(uint8_t buffer, uint32_t timeout) override { return run("search", buffer, 0, timeout); }
    SensorReply create_model(uint32_t timeout) override { return run("create", 0, 0, timeout); }
    SensorReply store(uint8_t buffer, uint16_t slot, uint32_t timeout) override { return run("store", buffer, slot, timeout); }
    SensorReply erase(uint16_t slot, uint32_t timeout) override { return run("erase", 0, slot, timeout); }
    SensorReply index(uint32_t timeout) override { return run("index", 0, 0, timeout); }
};

struct Fixture {
    Storage storage;
    MemoryAuditStorage audit_storage;
    AuditStore audit_store{audit_storage};
    AuditPublisher audit{audit_store, 32};
    Clock clock;
    Gate gate{clock};
    Sensor sensor{storage, clock};
    std::unique_ptr<FingerprintController> controller;
    bool touch = false;
    bool audit_available = true;
    std::bitset<UserRegistry::kSlotCount> occupied;

    void seed(uint16_t slot, Role role = Role::User, bool active = true)
    {
        UserStore store(storage);
        require(store.stage({slot, "User " + std::to_string(slot), role, active}) == StoreResult::Ok, "seed stage");
        require(store.commit(slot) == StoreResult::Ok, "seed commit");
        occupied.set(slot);
    }
    void boot(SensorCode code = SensorCode::Ok)
    {
        sensor.expect_index(occupied, code);
        if (audit_available) require(audit_store.initialize() == AuditResult::Ok, "audit store initialize");
        controller.reset(new FingerprintController(storage, sensor, gate, clock, audit));
        controller->initialize();
    }
    FingerprintSnapshot state() const { return controller->snapshot(); }
    void tick(uint64_t elapsed = 0)
    {
        clock.now += elapsed;
        const auto before = sensor.calls.size();
        controller->tick(touch);
        require(sensor.calls.size() - before <= 1, "more than one sensor operation per tick");
    }
    void ticks(unsigned count) { while (count--) tick(); }
    void release()
    {
        touch = false;
        tick();
        tick(30);
    }
    void press()
    {
        touch = true;
        tick();
        tick(29);
        tick(1);
    }
    std::string enroll(std::string name = {}, uint32_t id = 7, Role role = Role::User)
    {
        return controller->command({FingerprintCommandType::Enroll, 0, std::move(name), role, id});
    }
    void scan(uint8_t number, SensorCode duplicate = SensorCode::NotFound)
    {
        sensor.expect("capture");
        sensor.expect("convert", SensorCode::Ok, number);
        if (number == 1) sensor.expect("search", duplicate, 1);
        press();
        ticks(number == 1 ? 3 : 2);
    }
    void four_scans()
    {
        for (uint8_t scan_number = 1; scan_number <= 4; ++scan_number) {
            scan(scan_number);
            if (scan_number != 4) release();
        }
        require(state().enrollment_state == "create_model", "four scans must precede model creation");
    }
    void stage()
    {
        sensor.expect("create");
        tick();
        tick();
        require(state().enrollment_state == "store", "intent must precede store state");
    }
    void store(SensorCode code = SensorCode::Ok)
    {
        sensor.expect("store", code, 1, state().enrolled_slot);
        tick();
    }
    void recognition(uint16_t slot, uint64_t at)
    {
        release();
        require(at >= clock.now + 30, "test clock must remain monotonic");
        clock.now = at - 30;
        sensor.expect("capture");
        sensor.expect("convert", SensorCode::Ok, 1);
        sensor.expect("search", SensorCode::Ok, 1, slot);
        press();
        ticks(3);
    }
    void done() const { require(sensor.steps.empty(), "scripted transactions were not executed"); }
    std::vector<AuditRecord> events()
    {
        audit.drain(32);
        AuditPage page;
        require(audit_store.read_after({}, 32, &page) == AuditResult::Ok, "read audit events");
        return page.events;
    }
};

void test_boot_reconciliation_and_retry()
{
    Fixture f;
    f.seed(1);
    f.seed(2, Role::Master, false);
    f.seed(3);
    f.occupied.reset(3);
    f.occupied.set(4);
    UserStore store(f.storage);
    require(store.stage({5, "pending", Role::User, true}) == StoreResult::Ok, "pending add seed");
    f.seed(6);
    require(store.stage_delete(6) == StoreResult::Ok, "pending delete seed");
    f.occupied.reset(6);
    f.seed(7);
    require(store.stage_delete(7) == StoreResult::Ok, "present pending delete seed");
    f.storage.memory.put("u8", {255});
    f.boot(SensorCode::Uncertain);
    require(!f.state().ready, "failed boot index must deny readiness");
    require(f.enroll() == "not_ready", "failed index must deny enrollment");
    f.tick(4999);
    require(f.sensor.calls.size() == 1, "index retry must be rate limited");
    f.sensor.expect_index(f.occupied);
    f.tick(1);
    require(f.state().ready, "bounded retry should recover index");
    for (auto slot : {3, 4, 5, 7, 8}) require(f.state().quarantined.test(slot), "unresolved slot must quarantine");
    require(!f.state().quarantined.test(6), "absent pending delete should finalize metadata");
    require(!store.load().metadata.test(6), "pending deletion metadata not finalized");
    require(store.load().pending_add.test(5), "boot must preserve unresolved add intent");
    require(store.load().pending_delete.test(7), "boot must preserve present delete intent");
    f.recognition(1, 5100);
    require(f.gate.calls == 1, "unaffected active user should unlock");
    for (auto slot : {2, 3, 4, 5, 7, 8, 99}) {
        f.recognition(slot, f.clock.now + 10100);
        require(f.state().last_access == "denied", "denied slot must not merely be suppressed by cooldown");
    }
    require(f.gate.calls == 1, "inactive, orphaned, missing, pending and unknown slots must never pulse");
    f.done();

    Fixture read_error;
    read_error.seed(9);
    read_error.storage.fail("get", "u9");
    read_error.boot();
    require(read_error.state().quarantined.test(9), "failed read with valid bytes must not publish user");
    read_error.recognition(9, 100);
    require(read_error.gate.calls == 0, "storage read failure must deny access");
    read_error.done();
}

void test_debounce_held_finger_and_failed_attempt()
{
    Fixture f;
    f.seed(0);
    f.boot();
    f.touch = true;
    f.tick();
    f.tick(29);
    require(f.sensor.calls.size() == 1, "touch must be stable for 30 ms");
    f.touch = false;
    f.tick();
    f.tick(29);
    f.sensor.expect("capture");
    f.sensor.expect("convert", SensorCode::Ok, 1);
    f.sensor.expect("search", SensorCode::Ok, 1, 0);
    f.press();
    f.ticks(3);
    require(f.gate.calls == 1, "debounced touch must recognize slot zero");
    f.tick(20000);
    f.ticks(20);
    f.touch = false;
    f.tick();
    f.tick(29);
    f.touch = true;
    f.tick();
    f.tick(30);
    f.ticks(10);
    require(f.gate.calls == 1, "held finger and short release must not repeat attempt");
    f.release();
    f.sensor.expect("capture", SensorCode::NoFinger);
    f.press();
    f.tick();
    f.tick(20000);
    f.ticks(10);
    require(f.gate.calls == 1, "failed capture must not retry held finger in recognition");
    f.recognition(0, f.clock.now + 100);
    require(f.gate.calls == 2, "stable release must rearm recognition");
    f.done();
}

void test_gate_timestamp_cooldown_and_rejection()
{
    Fixture f;
    f.seed(1);
    f.boot();
    f.gate.accept = false;
    f.recognition(1, 100);
    require(f.state().last_access == "actuator_rejected", "actuator rejection must be observable");
    f.gate.accept = true;
    f.gate.timestamp_offset = 400;
    f.recognition(1, 200);
    require(f.gate.calls == 2, "rejected pulse must not start cooldown");
    f.gate.timestamp_offset = 0;
    f.recognition(1, 10599);
    require(f.gate.calls == 2 && f.state().last_access == "cooldown", "cooldown must use accepted actuator timestamp");
    f.recognition(1, 10699);
    require(f.gate.calls == 3, "cooldown matches must not extend cooldown");
    f.done();

    Fixture exact;
    exact.seed(1);
    exact.boot();
    exact.gate.timestamp_offset = 400;
    exact.recognition(1, 100);
    exact.gate.timestamp_offset = 0;
    exact.recognition(1, 10500);
    require(exact.gate.calls == 2, "exact 10000 ms boundary must accept a new pulse");
    exact.done();
}

void test_metadata_updates_and_master_limit()
{
    Fixture f;
    f.seed(1, Role::Master);
    f.seed(2, Role::Master);
    f.seed(3);
    f.boot();
    auto command = FingerprintCommand{FingerprintCommandType::SetRole, 3, {}, Role::Master};
    const auto before = f.storage.writes;
    require(f.controller->command(command) == "master_limit", "third master must fail before persistence");
    require(f.storage.writes == before, "invalid master promotion must not touch storage");
    command.slot = 2;
    command.role = Role::User;
    require(f.controller->command(command) == "ok", "master demotion");
    command.slot = 3;
    command.role = Role::Master;
    require(f.controller->command(command) == "ok", "promotion after demotion");
    require(!UserStore(f.storage).load().quarantined.any(), "metadata update must remain committed");
    command.type = FingerprintCommandType::Rename;
    command.name = std::string(65, 'a');
    require(f.controller->command(command) == "invalid_name", "oversized name must fail");
    command.name = "   ";
    require(f.controller->command(command) == "invalid_name", "blank name must fail");
    command.name = "Новое имя";
    require(f.controller->command(command) == "ok", "Unicode rename must persist");
    f.boot();
    require(f.state().users.at(2).name == command.name, "rename must survive reboot");
    require(f.state().users.at(2).role == Role::Master, "role update must survive reboot");
    f.storage.fail("put", "u3", true);
    command.name = "ambiguous";
    require(f.controller->command(command) == "storage_failed", "ambiguous update failure must be reported");
    require(f.state().quarantined.test(3), "ambiguous update must fail closed immediately");
    require(f.state().users.at(2).name == "Новое имя", "failed update must not publish new registry");
    f.recognition(3, 100);
    require(f.gate.calls == 0, "ambiguous metadata update must not grant access");
    require(UserStore(f.storage).load().pending_update.test(3), "failed update must retain its own operation kind");
    require(!UserStore(f.storage).load().pending_add.test(3), "metadata update must not become a pending enrollment");
    f.boot();
    require(f.state().quarantined.test(3), "ambiguous update must remain denied after reboot");
    f.recognition(3, 200);
    require(f.gate.calls == 0, "reboot must not authorize ambiguous metadata update");
    f.done();

    UserStore store(f.storage);
    require(store.stage({4, "pending", Role::User, true}) == StoreResult::Ok, "pending seed");
    require(store.update({4, "renamed", Role::User, true}) == StoreResult::Corrupt,
            "committed-only update must not finalize a pending add");
    require(store.load().pending_add.test(4), "pending operation kind must survive update rejection");
}

void test_four_scans_release_signals_and_default_role()
{
    Fixture f;
    f.boot();
    f.press();
    require(f.enroll({}, 42, Role::Master) == "ok", "enrollment should start");
    require(f.controller->take_signal() == FingerprintSignal::Enrollment, "start must publish yellow signal once");
    require(f.controller->take_signal() == FingerprintSignal::None, "signal must drain");
    require(f.state().enrollment_state == "remove_finger", "held finger must be removed before first scan");
    f.ticks(10);
    f.release();
    f.scan(1);
    f.ticks(10);
    require(f.state().scan == 2 && f.state().enrollment_state == "remove_finger", "scan one must wait for release");
    f.touch = false;
    f.tick();
    f.tick(29);
    f.touch = true;
    f.tick();
    f.tick(30);
    require(f.state().enrollment_state == "remove_finger", "short release must not advance enrollment");
    f.release();
    f.scan(2);
    f.release();
    f.scan(3);
    f.release();
    f.scan(4);
    f.stage();
    f.store();
    f.tick();
    require(!f.state().enrolling && f.state().enrollment_state == "success", "four scans must commit enrollment");
    require(f.state().operation_id == 42 && f.state().enrolled_slot == 0, "operation identity and slot must be published");
    require(f.state().users.size() == 1 && f.state().users[0].role == Role::User, "web role must default to User");
    require(f.state().users[0].name == "Палец №0", "default enrollment name");
    require(f.controller->take_signal() == FingerprintSignal::Success, "successful enrollment signal");
    f.tick(11000);
    f.ticks(20);
    require(f.gate.calls == 0, "successful enrollment must not recognize still-held finger");
    f.recognition(0, f.clock.now + 100);
    require(f.gate.calls == 1, "newly committed user must recognize after release");
    f.occupied.set(0);
    f.boot();
    f.recognition(0, f.clock.now + 10100);
    require(f.gate.calls == 2, "committed sensor and metadata must survive reboot");
    f.done();
}

void test_enrollment_duplicate_failure_nofinger_and_full()
{
    for (auto code : {SensorCode::Ok, SensorCode::Uncertain, SensorCode::Rejected, SensorCode::NoFinger}) {
        Fixture f;
        f.boot();
        f.release();
        require(f.enroll("Custom name") == "ok", "enroll start");
        f.scan(1, code);
        require(!f.state().enrolling && f.state().users.empty(), "only confirmed NotFound may pass duplicate check");
        require(f.controller->take_signal() == FingerprintSignal::Failure, "duplicate failure must signal");
        f.done();
    }
    Fixture retry;
    retry.boot();
    retry.release();
    require(retry.enroll() == "ok", "enroll start");
    retry.sensor.expect("capture", SensorCode::NoFinger);
    retry.sensor.expect("capture", SensorCode::NoFinger);
    retry.sensor.expect("capture");
    retry.sensor.expect("convert", SensorCode::Ok, 1);
    retry.sensor.expect("search", SensorCode::NotFound, 1);
    retry.press();
    retry.ticks(5);
    require(retry.state().enrolling && retry.state().scan == 2, "NoFinger must retry during enrollment");
    retry.done();

    Fixture full;
    full.occupied.set();
    full.boot();
    require(full.enroll() == "database_full" && full.state().message == "database_full", "full DB must be observable");
    full.done();

    Fixture excluded;
    excluded.seed(0);
    excluded.occupied.reset(0);
    UserStore(excluded.storage).stage({1, "pending", Role::User, true});
    excluded.occupied.set(2);
    excluded.boot();
    require(excluded.enroll("Name") == "ok" && excluded.state().enrolled_slot == 3,
            "free slot must exclude metadata, pending and sensor orphans");
    excluded.done();
}

void test_stale_cancel_busy_and_reboot_boundaries()
{
    for (unsigned boundary = 0; boundary != 3; ++boundary) {
        Fixture f;
        f.boot();
        f.release();
        require(f.enroll("Name", 20) == "ok", "enrollment start");
        require(f.controller->command({FingerprintCommandType::Cancel, 0, {}, Role::User, 19}) == "stale_cancel",
                "cancel must match current enrollment ID");
        require(f.enroll() == "busy", "parallel enrollment must be rejected");
        require(f.controller->command({FingerprintCommandType::Rename, 0, "x"}) == "busy", "mutations must be serialized");
        f.four_scans();
        if (boundary >= 1) f.stage();
        if (boundary >= 2) { f.store(); f.occupied.set(0); }
        f.boot();
        require(f.state().users.empty(), "reboot before commit must not authorize user");
        if (boundary >= 1) {
            require(f.state().quarantined.test(0), "pending add must remain quarantined even if sensor absent");
            require(UserStore(f.storage).load().pending_add.test(0), "boot must retain pending add kind");
        }
        f.done();
    }
    for (bool stored : {false, true}) {
        Fixture f;
        f.boot();
        f.release();
        require(f.enroll({}, 31) == "ok", "enrollment start");
        f.four_scans();
        f.stage();
        if (stored) { f.store(); f.occupied.set(0); }
        require(f.controller->command({FingerprintCommandType::Cancel, 0, {}, Role::User, 31}) == "ok", "matching cancel must succeed");
        require(!f.state().enrolling, "cancel must end enrollment");
        require(f.state().quarantined.test(0) == stored, "cancel after possible store must quarantine, before store may discard");
        require(UserStore(f.storage).load().pending_add.test(0) == stored, "cancel must retain uncertain mutation evidence");
        f.boot();
        require(f.state().quarantined.test(0) == stored, "cancel recovery must preserve uncertainty");
        require(f.controller->command({FingerprintCommandType::Cancel, 0, {}, Role::User, 31}) == "stale_cancel", "finished cancel must become stale");
        f.done();
    }
}

void test_uncertain_store_confirmation_and_quarantine()
{
    for (unsigned outcome = 0; outcome != 4; ++outcome) {
        Fixture f;
        f.boot();
        f.release();
        require(f.enroll() == "ok", "enroll start");
        f.four_scans();
        f.stage();
        f.store(SensorCode::Uncertain);
        f.occupied.set(0);
        f.sensor.expect_index(f.occupied, outcome == 3 ? SensorCode::Uncertain : SensorCode::Ok);
        f.tick();
        if (outcome != 3) {
            f.sensor.expect("search", outcome == 2 ? SensorCode::Uncertain : SensorCode::Ok, 1, outcome == 1 ? 99 : 0);
            f.tick();
        }
        if (outcome == 0) f.tick();
        require(!f.state().enrolling, "uncertain store must reach bounded terminal state");
        require(f.state().users.empty() == (outcome != 0), "only shaped index plus same-slot search confirms uncertain store");
        require(f.state().quarantined.test(0) == (outcome != 0), "unresolved store must quarantine");
        f.boot();
        require(f.state().users.empty() == (outcome != 0), "store confirmation state must survive reboot");
        f.done();
    }
    Fixture absent;
    absent.boot();
    absent.release();
    require(absent.enroll() == "ok", "enroll start");
    absent.four_scans();
    absent.stage();
    absent.store(SensorCode::Uncertain);
    absent.sensor.expect_index();
    absent.tick();
    absent.tick();
    require(!absent.state().enrolling && !absent.state().quarantined.any(), "confirmed absent store can discard intent safely");
    require(!UserStore(absent.storage).load().metadata.any(), "absent store must clear pending metadata");
    absent.done();
}

void test_commit_failure_compensation_and_reboot()
{
    for (unsigned outcome = 0; outcome != 5; ++outcome) {
        Fixture f;
        f.boot();
        f.release();
        require(f.enroll() == "ok", "enroll start");
        f.four_scans();
        f.stage();
        f.store();
        f.storage.fail("put", "u0", outcome >= 3);
        f.tick();
        f.sensor.expect("erase", outcome == 0 ? SensorCode::Ok : SensorCode::Uncertain, 0, 0);
        f.tick();
        if (outcome != 0) {
            f.occupied.set(0, outcome == 2 || outcome == 4);
            f.sensor.expect_index(f.occupied);
            f.tick();
        }
        if (outcome != 2 && outcome != 4) {
            if (outcome == 3) f.storage.fail("erase", "u0");
            f.tick();
        }
        require(!f.state().enrolling && f.state().users.empty(), "commit failure must not publish registry");
        require(f.state().quarantined.test(0) == (outcome >= 2), "compensation uncertainty must retain quarantine");
        const auto persisted = UserStore(f.storage).load();
        require(persisted.metadata.test(0) == (outcome >= 2), "intent must clear only after proven absence and metadata removal");
        f.boot();
        require(f.state().users.empty() || f.state().quarantined.test(0), "failed compensation must deny after reboot");
        f.done();
    }
    Fixture stage_failure;
    stage_failure.boot();
    stage_failure.release();
    require(stage_failure.enroll() == "ok", "enroll start");
    stage_failure.four_scans();
    stage_failure.sensor.expect("create");
    stage_failure.tick();
    stage_failure.storage.fail("put", "u0", true);
    stage_failure.tick();
    require(!stage_failure.state().enrolling && stage_failure.state().quarantined.test(0), "ambiguous stage must quarantine without sensor store");
    stage_failure.boot();
    require(stage_failure.state().quarantined.test(0), "ambiguous stage must survive reboot");
    stage_failure.done();
}

void test_delete_staging_uncertainty_and_recovery()
{
    for (unsigned outcome = 0; outcome != 5; ++outcome) {
        Fixture f;
        f.seed(4);
        f.boot();
        if (outcome == 0) f.storage.fail("put", "u4", true);
        else {
            f.sensor.expect("erase", outcome == 4 ? SensorCode::Ok : SensorCode::Uncertain, 0, 4);
            if (outcome != 4) {
                f.occupied.set(4, outcome == 2);
                f.sensor.expect_index(f.occupied, outcome == 3 ? SensorCode::Uncertain : SensorCode::Ok);
            } else {
                f.occupied.reset(4);
                f.storage.fail("erase", "u4");
            }
        }
        const auto result = f.controller->command({FingerprintCommandType::Delete, 4, {}});
        require((result == "ok") == (outcome == 1), "delete result must reflect sensor and metadata proof");
        require(f.state().quarantined.test(4) == (outcome != 1), "unresolved delete must deny immediately");
        if (outcome != 1) require(UserStore(f.storage).load().pending_delete.test(4), "delete operation kind must persist");
        f.boot();
        const bool unresolved = outcome == 0 || outcome == 2;
        require(f.state().quarantined.test(4) == unresolved, "reboot must finalize only proven absent deletes");
        f.recognition(4, 100);
        require(f.gate.calls == 0, "deleted or quarantined slot must never pulse");
        f.done();
    }
}

void test_intent_marker_boundaries()
{
    for (bool ambiguous : {false, true}) {
        for (const std::string operation : {"put", "erase"}) {
            Fixture f;
            f.boot();
            f.release();
            require(f.enroll() == "ok", "enrollment start");
            f.four_scans();
            f.stage();
            f.store();
            f.storage.fail(operation, "ui0", ambiguous);
            f.tick();
            const bool complete = operation == "erase" && ambiguous;
            if (!complete) {
                f.sensor.expect("erase", SensorCode::Uncertain, 0, 0);
                f.tick();
                f.occupied.set(0);
                f.sensor.expect_index(f.occupied);
                f.tick();
            } else f.occupied.set(0);
            require(f.state().users.empty() == !complete, "only proven marker removal completes commit");
            f.boot();
            require(f.state().quarantined.test(0) == !complete, "marker failure must deny after reboot");
            f.done();
        }
    }
    Fixture corrupt;
    corrupt.seed(1);
    corrupt.storage.memory.put("ui1", {255});
    corrupt.boot();
    require(corrupt.state().quarantined.test(1), "corrupt intent marker must suppress committed record");
    corrupt.recognition(1, 100);
    require(corrupt.gate.calls == 0, "corrupt marker must never authorize its slot");
    corrupt.done();
}

void test_chained_commit_faults_require_durable_guard()
{
    for (unsigned scenario = 0; scenario != 4; ++scenario) {
        const bool lost_guard_ack = scenario >= 2;
        const bool reboot_before_compensation = scenario % 2 == 0;
        Fixture f;
        f.boot();
        f.release();
        require(f.enroll() == "ok", "enrollment start");
        f.four_scans();
        f.stage();
        f.store();
        f.occupied.set(0);
        f.storage.fail("erase", "ui0", true);
        f.storage.fail("get", "ui0");
        if (lost_guard_ack) f.storage.fail("put", "uq0", true);
        f.tick();
        require(f.storage.faults.empty(), "both ambiguous erase and failed readback must execute");
        require(UserStore(f.storage).load().quarantined.test(0),
                "failed finalization must recreate durable quarantine before compensation");
        if (!reboot_before_compensation) {
            f.sensor.expect("erase", SensorCode::Uncertain, 0, 0);
            f.tick();
            f.sensor.expect_index(f.occupied);
            f.tick();
            require(!f.state().enrolling, "failed compensation must terminate");
        }
        f.boot();
        require(f.state().quarantined.test(0) && f.state().users.empty(),
                "chained finalization and compensation failures must remain denied after reboot");
        f.recognition(0, f.clock.now + 100);
        require(f.gate.calls == 0, "persisted rollback guard must prevent a pulse");
        f.done();
    }
}

void test_unconfirmed_guard_preserves_coherent_commit()
{
    for (unsigned outcome = 0; outcome != 4; ++outcome) {
        Fixture f;
        f.boot();
        f.release();
        require(f.enroll() == "ok", "enrollment start");
        f.four_scans();
        f.stage();
        f.store();
        f.occupied.set(0);
        if (outcome == 3) f.storage.fail("put", "u0");
        else {
            f.storage.fail("erase", "ui0", true);
            f.storage.fail("get", "ui0");
        }
        if (outcome >= 2) {
            f.storage.before_operation = [&](const std::string& operation, const std::string& key) {
                if (operation == "put" && key == "uq0") f.storage.unavailable = true;
            };
        } else {
            f.storage.fail("put", "uq0", outcome == 1);
            f.storage.fail("get", "uq0");
        }
        f.tick();
        require(!f.state().enrolling && f.state().message == "commit_indeterminate",
                "unconfirmed guard must explicitly report indeterminate commit");
        require(f.state().quarantined.test(0) && f.state().users.empty(), "indeterminate commit must deny in memory");
        f.ticks(5);
        f.done();
        f.storage.unavailable = false;
        f.storage.before_operation = {};
        require(f.storage.faults.empty(), "all chained guard faults must execute");
        f.boot();
        const bool denied = outcome == 1 || outcome == 3;
        require(f.state().quarantined.test(0) == denied,
                "reboot must honor surviving guard/intent, or recover untouched coherent committed template");
        f.recognition(0, f.clock.now + 100);
        require(f.gate.calls == (denied ? 0U : 1U), "recovery must reflect durable state without destructive compensation");
        f.done();
    }
}

void test_metadata_update_finalization_chain()
{
    for (bool guard_available : {true, false}) {
        Fixture f;
        f.seed(1);
        f.seed(2, Role::Master);
        f.boot();
        f.storage.fail("erase", "ui1", true);
        f.storage.fail("get", "ui1", false, 1);
        if (!guard_available) {
            f.storage.before_operation = [&](const std::string& operation, const std::string& key) {
                if (operation == "put" && key == "uq1") f.storage.unavailable = true;
            };
        }
        const auto calls = f.sensor.calls.size();
        require(f.controller->command({FingerprintCommandType::SetRole, 1, {}, Role::Master}) ==
                    (guard_available ? "storage_failed" : "update_indeterminate"),
                "failed metadata finalization must distinguish unconfirmed guard");
        require(f.sensor.calls.size() == calls, "metadata failure must never compensate by erasing existing template");
        require(f.state().quarantined.test(1) && f.state().users.front().role == Role::User,
                "failed metadata update must not publish role");
        f.storage.unavailable = false;
        f.storage.before_operation = {};
        require(f.storage.faults.empty(), "metadata erase/readback fault chain must execute");
        f.boot();
        require(f.state().quarantined.test(1) == guard_available, "reboot must honor confirmed metadata guard");
        f.recognition(2, 100);
        require(f.gate.calls == 1, "unrelated existing template must remain usable");
        f.recognition(1, 10200);
        require(f.gate.calls == (guard_available ? 1U : 2U), "indeterminate metadata recovery must preserve coherent template");
        f.done();
    }
}

void test_storage_calls_crossing_deadline(bool commit, bool guard_available = true)
{
    Fixture f;
    f.boot();
    f.release();
    const auto started = f.clock.now;
    require(f.enroll() == "ok", "enrollment start");
    f.four_scans();
    if (commit) {
        f.stage();
        f.store();
        f.occupied.set(0);
    } else {
        f.sensor.expect("create");
        f.tick();
    }
    f.clock.now = started + 119999;
    bool delayed = false;
    f.storage.before_operation = [&](const std::string& operation, const std::string& key) {
        if (!delayed && operation == "put" && key == "u0") {
            ++f.clock.now;
            delayed = true;
        }
        if (!guard_available && operation == "put" && key == "uq0") f.storage.unavailable = true;
    };
    f.tick();
    const bool indeterminate = commit && !guard_available;
    require(delayed, "persistence must advance fake clock across absolute deadline");
    require(!f.state().enrolling && f.state().message == (indeterminate ? "commit_indeterminate" : "timeout"),
            "persistence deadline must be checked in same tick, with explicit uncertainty if guard cannot persist");
    require(f.state().users.empty(), "late metadata commit must not publish enrollment");
    require(f.controller->take_signal() == FingerprintSignal::Failure, "expired persistence must not emit success");
    f.storage.before_operation = {};
    f.storage.unavailable = false;
    f.tick();
    f.done();
    f.boot();
    require(f.state().users.empty() == !indeterminate,
            "durable guard must deny late commit; storage outage may leave coherent committed state");
    require(f.state().quarantined.test(0) == (commit && guard_available),
            "late stage may discard safely; late commit must retain any confirmed guard");
    f.done();
}

void test_guard_storage_crossing_deadline()
{
    Fixture f;
    f.boot();
    f.release();
    const auto started = f.clock.now;
    require(f.enroll() == "ok", "enrollment start");
    f.four_scans();
    f.stage();
    f.store();
    f.occupied.set(0);
    f.clock.now = started + 119999;
    f.storage.fail("put", "u0");
    bool delayed = false;
    f.storage.before_operation = [&](const std::string& operation, const std::string& key) {
        if (operation == "put" && key == "uq0") {
            ++f.clock.now;
            delayed = true;
        }
    };
    f.tick();
    require(delayed && !f.state().enrolling && f.state().message == "timeout",
            "blocking guard persistence must not permit compensation after deadline");
    f.storage.before_operation = {};
    f.tick();
    f.boot();
    require(f.state().quarantined.test(0) && f.state().users.empty(), "late guard must still suppress enrollment after reboot");
    f.done();
}

void test_sensor_failures_and_invalid_match()
{
    for (const std::string operation : {"capture", "convert", "search"}) {
        Fixture f;
        f.seed(1);
        f.boot();
        f.sensor.expect("capture", operation == "capture" ? SensorCode::Uncertain : SensorCode::Ok);
        if (operation != "capture")
            f.sensor.expect("convert", operation == "convert" ? SensorCode::Rejected : SensorCode::Ok, 1);
        if (operation == "search") f.sensor.expect("search", SensorCode::Uncertain, 1);
        f.press();
        f.ticks(3);
        f.tick(20000);
        f.ticks(20);
        require(f.gate.calls == 0, "failed recognition must never pulse or repeat held finger");
        require(f.controller->take_signal() == FingerprintSignal::Failure, "failed recognition must signal");
        f.done();
    }
    Fixture invalid;
    invalid.boot();
    invalid.recognition(100, 100);
    require(invalid.gate.calls == 0, "out-of-range match must fail closed without bitset exception");
    invalid.done();

    Fixture create_failure;
    create_failure.boot();
    create_failure.release();
    require(create_failure.enroll() == "ok", "enrollment start");
    create_failure.four_scans();
    create_failure.sensor.expect("create", SensorCode::Rejected);
    create_failure.tick();
    require(!create_failure.state().enrolling && !UserStore(create_failure.storage).load().metadata.any(),
            "failed model creation must not stage or store template");
    create_failure.done();

    Fixture rejected;
    rejected.boot();
    rejected.release();
    require(rejected.enroll() == "ok", "enrollment start");
    rejected.four_scans();
    rejected.stage();
    rejected.store(SensorCode::Rejected);
    rejected.tick();
    require(!rejected.state().enrolling && !UserStore(rejected.storage).load().metadata.any(),
            "explicitly rejected store may discard intent without retrying mutation");
    rejected.done();
}

void test_deadline_budgets_and_post_store_timeout()
{
    for (const std::string phase : {"capture", "convert", "duplicate", "create", "store", "verify_index", "verify_search", "rollback"}) {
        Fixture f;
        f.boot();
        f.release();
        const auto started = f.clock.now;
        require(f.enroll() == "ok", "enroll start");
        if (phase == "capture" || phase == "convert" || phase == "duplicate") {
            f.press();
            if (phase != "capture") { f.sensor.expect("capture"); f.tick(); }
            if (phase == "duplicate") { f.sensor.expect("convert", SensorCode::Ok, 1); f.tick(); }
        } else {
            f.four_scans();
            if (phase != "create") f.stage();
            if (phase == "verify_index" || phase == "verify_search") {
                f.store(SensorCode::Uncertain);
                if (phase == "verify_search") {
                    f.occupied.set(0);
                    f.sensor.expect_index(f.occupied);
                    f.tick();
                }
            } else if (phase == "rollback") {
                f.store();
                f.storage.fail("put", "u0");
                f.tick();
            }
        }
        if (phase == "capture") f.sensor.expect("capture");
        else if (phase == "convert") f.sensor.expect("convert", SensorCode::Ok, 1);
        else if (phase == "duplicate") f.sensor.expect("search", SensorCode::NotFound, 1);
        else if (phase == "create") f.sensor.expect("create");
        else if (phase == "store") f.sensor.expect("store", SensorCode::Ok, 1, 0);
        else if (phase == "verify_index") f.sensor.expect_index();
        else if (phase == "verify_search") f.sensor.expect("search", SensorCode::Ok, 1, 0);
        else f.sensor.expect("erase", SensorCode::Uncertain, 0, 0);
        f.sensor.steps.back().expected_timeout = 1;
        f.sensor.steps.back().elapsed = 1;
        f.clock.now = started + 119999;
        f.tick();
        f.tick();
        require(!f.state().enrolling && f.state().message == "timeout", "absolute deadline must stop enrollment");
        require(f.state().users.empty(), "deadline must not publish user");
        if (phase == "store" || phase == "verify_index" || phase == "verify_search" || phase == "rollback") {
            require(f.state().quarantined.test(0), "deadline after possible store must retain quarantine");
            require(UserStore(f.storage).load().metadata.test(0), "deadline must not forget mutation intent");
        }
        f.done();
    }
    Fixture waiting;
    waiting.boot();
    waiting.release();
    require(waiting.enroll() == "ok", "enroll start");
    waiting.tick(120000);
    require(!waiting.state().enrolling && waiting.state().message == "timeout", "waiting for finger must share absolute deadline");
    waiting.done();
}

void test_master_gesture_release_reset_and_fixed_window()
{
    Fixture f;
    f.seed(1, Role::Master);
    f.seed(2, Role::Master);
    f.seed(3);
    f.boot();
    f.recognition(1, 100);
    f.tick(50);
    f.ticks(20);
    require(!f.state().enrolling, "held master must count once");
    f.recognition(1, 300);
    f.recognition(2, 500);
    f.recognition(1, 700);
    f.recognition(1, 900);
    require(!f.state().enrolling, "different master must reset previous gesture");
    f.recognition(3, 1100);
    f.recognition(1, 1300);
    f.recognition(1, 1500);
    require(!f.state().enrolling, "user match must reset master gesture");
    f.recognition(1, 1700);
    require(!f.state().enrolling, "third master must release before enrollment");
    require(f.gate.calls == 1, "cooldown matches must count toward gesture without extra pulses");
    f.release();
    require(f.state().enrolling, "third stable release must start one local enrollment");
    require((f.state().operation_id & (uint32_t{1} << 31)) != 0, "local operation ID namespace");
    const auto id = f.state().operation_id;
    f.ticks(20);
    require(f.state().operation_id == id, "one gesture must start exactly one enrollment");
    require(f.controller->take_signal() == FingerprintSignal::Enrollment, "local enrollment must publish start signal");
    f.four_scans();
    f.stage();
    f.store();
    f.tick();
    require(!f.state().enrolling && f.state().users.size() == 4 && f.state().users.front().role == Role::User,
            "local gesture enrollment must create User even with two active Masters");
    require(f.gate.calls == 1, "local enrollment must not pulse the gate");
    f.done();

    Fixture window;
    window.seed(1, Role::Master);
    window.boot();
    window.recognition(1, 100);
    window.recognition(1, 9900);
    window.recognition(1, 10100);
    window.release();
    require(!window.state().enrolling, "gesture window must be fixed, not sliding; exact expiry resets");
    window.recognition(1, 10300);
    window.release();
    require(!window.state().enrolling, "expired gesture must restart count at one");
    window.recognition(1, 10500);
    window.release();
    require(window.state().enrolling, "three matches in restarted window must enroll");
    window.done();
}

void test_persistent_audit_producers()
{
    Fixture f;
    f.seed(1, Role::Master);
    f.boot();
    f.recognition(1, 100);
    f.recognition(99, 10200);
    f.recognition(99, 10300);
    const auto before_accepted = f.events().size();
    f.recognition(1, 10400);
    const auto events = f.events();
    require(events.size() == before_accepted + 2, "accepted match and gate decision must never be rate limited");
    require(events[0].type == AuditType::Access && events[0].result == AuditResultCode::Granted &&
                events[0].source == AuditSource::Fingerprint && events[0].slot == 1,
            "successful match audit fields");
    require(events[1].type == AuditType::Gate && events[1].result == AuditResultCode::Granted,
            "gate decision audit fields");
    require(events[2].type == AuditType::Access && events[2].result == AuditResultCode::Rejected &&
                events[2].slot == 99,
            "rejected match audit fields");
    require(events[3].type == AuditType::Access && events[3].result == AuditResultCode::Granted,
            "later accepted match audit fields");
    require(events[4].type == AuditType::Gate && events[4].result == AuditResultCode::Granted,
            "later gate decision audit fields");
    f.done();
}

void test_enrollment_and_user_mutation_audit_fields()
{
    Fixture f;
    f.seed(1);
    f.boot();
    require(f.controller->command({FingerprintCommandType::Rename, 1, "Alice"}) == "ok", "rename user");
    auto events = f.events();
    require(events.size() == 1 && events[0].type == AuditType::User &&
                events[0].result == AuditResultCode::Accepted && events[0].source == AuditSource::Admin &&
                events[0].slot == 1 && std::string(events[0].name.data()) == "Alice",
            "user mutation audit fields");

    f.release();
    require(f.enroll("Bob", 42) == "ok", "enrollment start");
    f.four_scans();
    f.stage();
    f.store();
    f.tick();
    events = f.events();
    require(events.size() == 2 && events[1].type == AuditType::Enrollment &&
                events[1].result == AuditResultCode::Granted && events[1].source == AuditSource::Admin &&
                events[1].slot == 0 && std::string(events[1].name.data()) == "Bob",
            "enrollment completion audit fields");
    f.done();
}

void test_audit_storage_waits_for_recognition_idle()
{
    Fixture f;
    f.seed(1);
    f.boot();
    f.sensor.expect("capture");
    f.sensor.expect("convert", SensorCode::Ok, 1);
    f.sensor.expect("search", SensorCode::Ok, 1, 1);
    f.press();
    require(!f.controller->audit_idle(), "capture must defer audit storage");
    f.ticks(3);
    require(f.controller->audit_idle(), "completed recognition may drain audit storage");
    f.done();
}

void test_audit_failure_does_not_block_local_access()
{
    Fixture f;
    f.audit_available = false;
    f.seed(1);
    f.boot();
    f.recognition(1, 100);
    require(f.gate.calls == 1 && f.state().last_access == "granted", "audit storage failure must not change access");
    require(f.audit.drain(8) == 0 && f.audit.failed_count() == 2, "unavailable audit records must be dropped after access");
    f.done();
}

}

int main(int argc, char** argv)
{
    const std::pair<const char*, std::function<void()>> tests[] = {
        {"boot reconciliation and retry", test_boot_reconciliation_and_retry},
        {"debounce and held finger", test_debounce_held_finger_and_failed_attempt},
        {"actuator timestamp cooldown", test_gate_timestamp_cooldown_and_rejection},
        {"metadata updates and master limit", test_metadata_updates_and_master_limit},
        {"four scans and release", test_four_scans_release_signals_and_default_role},
        {"duplicates NoFinger and full DB", test_enrollment_duplicate_failure_nofinger_and_full},
        {"cancel and reboot boundaries", test_stale_cancel_busy_and_reboot_boundaries},
        {"uncertain store confirmation", test_uncertain_store_confirmation_and_quarantine},
        {"commit compensation", test_commit_failure_compensation_and_reboot},
        {"delete recovery", test_delete_staging_uncertainty_and_recovery},
        {"intent marker boundaries", test_intent_marker_boundaries},
        {"chained commit faults", test_chained_commit_faults_require_durable_guard},
        {"unconfirmed guard", test_unconfirmed_guard_preserves_coherent_commit},
        {"metadata finalization chain", test_metadata_update_finalization_chain},
        {"storage deadline stage", [] { test_storage_calls_crossing_deadline(false); }},
        {"storage deadline commit", [] { test_storage_calls_crossing_deadline(true); }},
        {"storage deadline indeterminate", [] { test_storage_calls_crossing_deadline(true, false); }},
        {"storage deadline guard", test_guard_storage_crossing_deadline},
        {"sensor failures", test_sensor_failures_and_invalid_match},
        {"absolute deadline budgets", test_deadline_budgets_and_post_store_timeout},
        {"master gesture", test_master_gesture_release_reset_and_fixed_window},
        {"persistent audit producers", test_persistent_audit_producers},
        {"enrollment and user audit producers", test_enrollment_and_user_mutation_audit_fields},
        {"audit storage recognition idle", test_audit_storage_waits_for_recognition_idle},
        {"audit failure preserves local access", test_audit_failure_does_not_block_local_access},
    };
    unsigned executed = 0;
    for (const auto& test : tests) {
        if (argc > 1 && std::string(test.first).find(argv[1]) == std::string::npos) continue;
        current_test = test.first;
        test.second();
        std::cout << "PASS " << test.first << '\n';
        ++executed;
    }
    require(executed != 0, "no test matched requested filter");
    return EXIT_SUCCESS;
}
