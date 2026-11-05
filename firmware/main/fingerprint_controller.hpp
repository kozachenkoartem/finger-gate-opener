#pragma once

#include <bitset>
#include <cstdint>
#include <string>
#include <vector>

#include "user_store.hpp"
#include "audit_events.hpp"

namespace fg {

enum class SensorCode { Ok, NoFinger, NotFound, Rejected, Uncertain };
struct SensorReply {
    SensorCode code = SensorCode::Uncertain;
    uint16_t slot = 0;
    std::bitset<UserRegistry::kSlotCount> occupied;
};

class FingerprintSensor {
public:
    virtual ~FingerprintSensor() = default;
    virtual SensorReply capture(uint32_t timeout_ms) = 0;
    virtual SensorReply convert(uint8_t buffer, uint32_t timeout_ms) = 0;
    virtual SensorReply search(uint8_t buffer, uint32_t timeout_ms) = 0;
    virtual SensorReply create_model(uint32_t timeout_ms) = 0;
    virtual SensorReply store(uint8_t buffer, uint16_t slot, uint32_t timeout_ms) = 0;
    virtual SensorReply erase(uint16_t slot, uint32_t timeout_ms) = 0;
    virtual SensorReply index(uint32_t timeout_ms) = 0;
};

struct PulseResult { bool accepted = false; uint64_t started_ms = 0; };
class FingerprintGate {
public:
    virtual ~FingerprintGate() = default;
    virtual PulseResult pulse() = 0;
};
class FingerprintClock {
public:
    virtual ~FingerprintClock() = default;
    virtual uint64_t now_ms() const = 0;
};

enum class FingerprintCommandType { Enroll, Cancel, Rename, SetRole, Delete, HubOpen };
struct FingerprintCommand {
    FingerprintCommandType type;
    uint16_t slot = 0;
    std::string name;
    Role role = Role::User;
    uint32_t operation_id = 0;
    AuditSource source = AuditSource::Admin;
    std::string request_id;
};
enum class FingerprintSignal { None, Success, Failure, Enrollment };
struct FingerprintSnapshot {
    bool ready = false;
    std::vector<User> users;
    std::bitset<100> quarantined;
    std::string enrollment_state = "idle";
    std::string message;
    uint8_t scan = 0;
    uint16_t enrolled_slot = 0;
    uint32_t operation_id = 0;
    bool enrolling = false;
    std::string last_access;
    uint16_t last_match_slot = 0;
};

class FingerprintController {
public:
    FingerprintController(KeyValueStore&, FingerprintSensor&, FingerprintGate&, FingerprintClock&, AuditPublisher&);
    void initialize();
    std::string command(const FingerprintCommand&);
    void tick(bool touch_active);
    FingerprintSnapshot snapshot() const;
    FingerprintSignal take_signal();
    bool audit_idle() const;

private:
    enum class Recognition { Idle, Capture, Convert, Search };
    enum class Enrollment {
        Idle, Release, Touch, Capture, Convert, Duplicate, Create, Stage, Store,
        VerifyIndex, VerifySearch, Commit, Rollback, RollbackIndex, Discard
    };
    static constexpr auto kDebounceMs = 30U;
    static constexpr auto kRetryMs = 5000U;
    static constexpr auto kEnrollmentMs = 120000U;
    static constexpr auto kCooldownMs = 10000U;
    static constexpr auto kShortWaitMs = 300U;
    static constexpr auto kSearchWaitMs = 750U;
    static constexpr auto kMutationWaitMs = 500U;
    static constexpr auto kLocalIdBit = uint32_t{1} << 31;

    std::string start_enrollment(const std::string&, uint32_t, AuditSource source);
    void enrollment_tick();
    void finish_enrollment(bool success, const std::string& message);
    void abort_enrollment(const std::string& message);
    void recognition_tick();
    void match(uint16_t slot);
    void reset_gesture();
    void quarantine(uint16_t slot);
    uint32_t wait_budget(uint32_t maximum) const;
    void publish(AuditType type, AuditResultCode result, uint16_t slot, const std::string& name = {},
                 AuditSource source = AuditSource::Fingerprint);
    void rejected_match(uint16_t slot);
    std::string hub_open(const FingerprintCommand& command);

    UserStore store_;
    FingerprintSensor& sensor_;
    FingerprintGate& gate_;
    FingerprintClock& clock_;
    AuditPublisher& audit_;
    UserRegistry registry_;
    std::bitset<UserRegistry::kSlotCount> occupied_;
    std::bitset<UserRegistry::kSlotCount> metadata_;
    FingerprintSnapshot status_;
    FingerprintSignal signal_ = FingerprintSignal::None;
    Recognition recognition_ = Recognition::Idle;
    Enrollment enrollment_ = Enrollment::Idle;
    User candidate_;
    bool initialized_ = false;
    uint64_t last_initialize_ms_ = 0;
    bool raw_touch_ = false;
    bool stable_touch_ = false;
    bool release_known_ = false;
    uint64_t touch_changed_ms_ = 0;
    bool armed_ = true;
    uint64_t enrollment_started_ms_ = 0;
    bool staged_ = false;
    bool store_attempted_ = false;
    bool pulse_started_ = false;
    uint64_t pulse_started_ms_ = 0;
    uint16_t gesture_slot_ = 0;
    uint8_t gesture_count_ = 0;
    uint64_t gesture_started_ms_ = 0;
    bool local_enrollment_pending_ = false;
    uint32_t local_operation_id_ = kLocalIdBit;
    AuditSource enrollment_source_ = AuditSource::Admin;
    uint64_t last_rejected_audit_ms_ = 0;
    bool has_rejected_audit_ = false;
};

}
