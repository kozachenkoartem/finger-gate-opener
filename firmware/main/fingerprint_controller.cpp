#include "fingerprint_controller.hpp"

#include <algorithm>
#include <cstring>

namespace fg {
namespace {
bool removed(StoreResult result)
{
    return result == StoreResult::Ok || result == StoreResult::NotFound;
}

std::string registry_error(RegistryResult result)
{
    switch (result) {
    case RegistryResult::Ok: return "ok";
    case RegistryResult::InvalidSlot: return "invalid_slot";
    case RegistryResult::InvalidName: return "invalid_name";
    case RegistryResult::MasterLimitReached: return "master_limit";
    case RegistryResult::SlotAlreadyExists: return "slot_exists";
    case RegistryResult::NotFound: return "not_found";
    }
    return "invalid_command";
}
}

FingerprintController::FingerprintController(KeyValueStore& storage, FingerprintSensor& sensor,
                                            FingerprintGate& gate, FingerprintClock& clock, AuditPublisher& audit)
    : store_(storage), sensor_(sensor), gate_(gate), clock_(clock), audit_(audit)
{
}

bool FingerprintController::audit_idle() const
{
    return recognition_ == Recognition::Idle && !status_.enrolling;
}

void FingerprintController::publish(AuditType type, AuditResultCode result, uint16_t slot, const std::string& name,
                                    AuditSource source)
{
    AuditRecord event;
    event.type = type;
    event.result = result;
    event.source = source;
    event.slot = slot;
    event.elapsed_ms = clock_.now_ms();
    std::memcpy(event.name.data(), name.data(), std::min(name.size(), event.name.size() - 1));
    audit_.publish(event);
}

void FingerprintController::rejected_match(uint16_t slot)
{
    const auto now = clock_.now_ms();
    if (has_rejected_audit_ && now - last_rejected_audit_ms_ < kRetryMs) return;
    has_rejected_audit_ = true;
    last_rejected_audit_ms_ = now;
    publish(AuditType::Access, AuditResultCode::Rejected, slot);
}

void FingerprintController::initialize()
{
    if (status_.enrolling || status_.ready) return;
    initialized_ = true;
    last_initialize_ms_ = clock_.now_ms();
    const auto persisted = store_.load();
    registry_ = persisted.registry;
    metadata_ = persisted.metadata;
    status_.quarantined |= persisted.quarantined;
    const auto reply = sensor_.index(kShortWaitMs);
    if (reply.code != SensorCode::Ok) {
        status_.message = "index_failed";
        return;
    }
    occupied_ = reply.occupied;
    for (uint16_t slot = 0; slot < UserRegistry::kSlotCount; ++slot) {
        // Отсутствие шаблона доказывает завершение удаления, но не добавления.
        if (persisted.pending_delete.test(slot) && !occupied_.test(slot) &&
            removed(store_.commit_delete(slot))) {
            metadata_.reset(slot);
            status_.quarantined.reset(slot);
        }
        if ((registry_.find(slot) && !occupied_.test(slot)) ||
            (occupied_.test(slot) && !registry_.find(slot))) quarantine(slot);
    }
    status_.ready = true;
    status_.message = "ready";
}

void FingerprintController::quarantine(uint16_t slot)
{
    if (slot < UserRegistry::kSlotCount) status_.quarantined.set(slot);
}

std::string FingerprintController::command(const FingerprintCommand& command)
{
    if (command.type == FingerprintCommandType::Cancel) {
        if (!status_.enrolling || command.operation_id != status_.operation_id) return "stale_cancel";
        abort_enrollment("cancelled");
        return "ok";
    }
    if (!status_.ready) return "not_ready";
    if (status_.enrolling) return "busy";
    if (command.type == FingerprintCommandType::Enroll)
        return start_enrollment(command.name, command.operation_id, command.source);
    if (command.type == FingerprintCommandType::HubOpen) return hub_open(command);
    if (command.slot >= UserRegistry::kSlotCount) return "invalid_slot";
    if (status_.quarantined.test(command.slot)) return "slot_quarantined";
    const auto previous = registry_.find(command.slot);
    if (!previous) return "not_found";

    if (command.type == FingerprintCommandType::Delete) {
        // Даже неоднозначная ошибка записи намерения закрывает доступ к слоту.
        quarantine(command.slot);
        if (store_.stage_delete(command.slot) != StoreResult::Ok) return "storage_failed";
        const auto reply = sensor_.erase(command.slot, kMutationWaitMs);
        bool absent = reply.code == SensorCode::Ok;
        if (!absent) {
            const auto index = sensor_.index(kShortWaitMs);
            absent = index.code == SensorCode::Ok && !index.occupied.test(command.slot);
        }
        if (!absent) return "delete_uncertain";
        occupied_.reset(command.slot);
        if (!removed(store_.commit_delete(command.slot))) return "storage_failed";
        registry_.remove(command.slot);
        metadata_.reset(command.slot);
        status_.quarantined.reset(command.slot);
        reset_gesture();
        publish(AuditType::User, AuditResultCode::Accepted, command.slot, previous->name, command.source);
        return "ok";
    }

    UserRegistry next = registry_;
    RegistryResult result;
    if (command.type == FingerprintCommandType::Rename) {
        result = next.rename(command.slot, command.name);
    } else if (command.type == FingerprintCommandType::SetRole) {
        if (command.role != Role::User && command.role != Role::Master) return "invalid_role";
        result = next.set_role(command.slot, command.role);
    } else {
        return "invalid_command";
    }
    if (result != RegistryResult::Ok) return registry_error(result);
    if (store_.update(*next.find(command.slot)) != StoreResult::Ok) {
        quarantine(command.slot);
        // Финальное удаление uiN могло завершиться без подтверждения: ставим новый запрет.
        return store_.quarantine(command.slot) == StoreResult::Ok ? "storage_failed" : "update_indeterminate";
    }
    registry_ = std::move(next);
    reset_gesture();
    publish(AuditType::User, AuditResultCode::Accepted, command.slot, command.name.empty() ? previous->name : command.name,
            command.source);
    return "ok";
}

std::string FingerprintController::hub_open(const FingerprintCommand& command)
{
    const auto now = clock_.now_ms();
    if (pulse_started_ && (now < pulse_started_ms_ || now - pulse_started_ms_ < kCooldownMs)) {
        return "cooldown";
    }
    const auto pulse = gate_.pulse();
    if (!pulse.accepted) return "actuator_rejected";
    pulse_started_ = true;
    pulse_started_ms_ = pulse.started_ms;
    return "granted";
}

std::string FingerprintController::start_enrollment(const std::string& name, uint32_t operation_id, AuditSource source)
{
    uint16_t slot = 0;
    for (; slot < UserRegistry::kSlotCount; ++slot) {
        if (!occupied_.test(slot) && !metadata_.test(slot) &&
            !status_.quarantined.test(slot) && !registry_.find(slot)) break;
    }
    if (slot == UserRegistry::kSlotCount) {
        status_.message = "database_full";
        return "database_full";
    }
    candidate_ = {slot, name.empty() ? "Палец №" + std::to_string(slot) : name, Role::User, true};
    auto validation = registry_;
    const auto result = validation.add(candidate_);
    if (result != RegistryResult::Ok) return registry_error(result);
    status_.operation_id = operation_id;
    status_.enrolled_slot = slot;
    status_.scan = 1;
    status_.enrolling = true;
    status_.message = "enrollment_started";
    enrollment_started_ms_ = clock_.now_ms();
    enrollment_source_ = source;
    staged_ = false;
    store_attempted_ = false;
    enrollment_ = release_known_ && !raw_touch_ && !stable_touch_ ? Enrollment::Touch : Enrollment::Release;
    recognition_ = Recognition::Idle;
    armed_ = false;
    reset_gesture();
    signal_ = FingerprintSignal::Enrollment;
    return "ok";
}

uint32_t FingerprintController::wait_budget(uint32_t maximum) const
{
    const auto elapsed = clock_.now_ms() - enrollment_started_ms_;
    if (elapsed >= kEnrollmentMs) return 0;
    return static_cast<uint32_t>(std::min<uint64_t>(maximum, kEnrollmentMs - elapsed));
}

void FingerprintController::finish_enrollment(bool success, const std::string& message)
{
    status_.message = message;
    status_.enrollment_state = success ? "success" : message == "cancelled" ? "cancelled" : "failed";
    status_.enrolling = false;
    enrollment_ = Enrollment::Idle;
    recognition_ = Recognition::Idle;
    armed_ = release_known_ && !stable_touch_ && !raw_touch_;
    signal_ = success ? FingerprintSignal::Success : FingerprintSignal::Failure;
    publish(AuditType::Enrollment, success ? AuditResultCode::Granted : AuditResultCode::Failed, candidate_.slot,
            candidate_.name, enrollment_source_);
}

void FingerprintController::abort_enrollment(const std::string& message)
{
    if (store_attempted_) {
        // После возможной записи сохраняем журнал: повторная загрузка не даст доступ.
        quarantine(candidate_.slot);
    } else if (staged_) {
        if (removed(store_.commit_delete(candidate_.slot))) metadata_.reset(candidate_.slot);
        else quarantine(candidate_.slot);
    }
    finish_enrollment(false, message);
}

void FingerprintController::enrollment_tick()
{
    if (wait_budget(kShortWaitMs) == 0) {
        abort_enrollment("timeout");
        return;
    }
    switch (enrollment_) {
    case Enrollment::Idle: break;
    case Enrollment::Release:
        if (release_known_ && !raw_touch_ && !stable_touch_) enrollment_ = Enrollment::Touch;
        break;
    case Enrollment::Touch:
        if (raw_touch_ && stable_touch_) {
            enrollment_ = Enrollment::Capture;
        }
        break;
    case Enrollment::Capture: {
        const auto reply = sensor_.capture(wait_budget(kShortWaitMs));
        if (reply.code == SensorCode::Ok) enrollment_ = Enrollment::Convert;
        else if (reply.code == SensorCode::NoFinger) {
            if (!stable_touch_) enrollment_ = Enrollment::Touch;
        } else finish_enrollment(false, "capture_failed");
        break;
    }
    case Enrollment::Convert: {
        const auto reply = sensor_.convert(status_.scan, wait_budget(kShortWaitMs));
        if (reply.code != SensorCode::Ok) finish_enrollment(false, "convert_failed");
        else if (status_.scan == 1) enrollment_ = Enrollment::Duplicate;
        else if (status_.scan == 4) enrollment_ = Enrollment::Create;
        else {
            ++status_.scan;
            enrollment_ = Enrollment::Release;
        }
        break;
    }
    case Enrollment::Duplicate: {
        const auto reply = sensor_.search(1, wait_budget(kSearchWaitMs));
        if (reply.code == SensorCode::NotFound) {
            ++status_.scan;
            enrollment_ = Enrollment::Release;
        } else finish_enrollment(false, reply.code == SensorCode::Ok ? "duplicate" : "duplicate_search_failed");
        break;
    }
    case Enrollment::Create:
        if (sensor_.create_model(wait_budget(kShortWaitMs)).code == SensorCode::Ok)
            enrollment_ = Enrollment::Stage;
        else finish_enrollment(false, "create_failed");
        break;
    case Enrollment::Stage: {
        metadata_.set(candidate_.slot);
        const auto result = store_.stage(candidate_);
        if (result == StoreResult::Ok) {
            staged_ = true;
            if (wait_budget(kShortWaitMs) == 0) abort_enrollment("timeout");
            else enrollment_ = Enrollment::Store;
        } else {
            quarantine(candidate_.slot);
            finish_enrollment(false, wait_budget(kShortWaitMs) == 0 ? "timeout" : "storage_failed");
        }
        break;
    }
    case Enrollment::Store: {
        store_attempted_ = true;
        const auto reply = sensor_.store(1, candidate_.slot, wait_budget(kMutationWaitMs));
        if (reply.code == SensorCode::Ok) {
            occupied_.set(candidate_.slot);
            enrollment_ = Enrollment::Commit;
        } else if (reply.code == SensorCode::Uncertain) {
            quarantine(candidate_.slot);
            enrollment_ = Enrollment::VerifyIndex;
        } else {
            status_.message = "store_rejected";
            enrollment_ = Enrollment::Discard;
        }
        break;
    }
    case Enrollment::VerifyIndex: {
        const auto reply = sensor_.index(wait_budget(kShortWaitMs));
        if (reply.code != SensorCode::Ok) finish_enrollment(false, "store_uncertain");
        else if (reply.occupied.test(candidate_.slot)) {
            occupied_.set(candidate_.slot);
            enrollment_ = Enrollment::VerifySearch;
        } else {
            occupied_.reset(candidate_.slot);
            status_.message = "store_not_present";
            enrollment_ = Enrollment::Discard;
        }
        break;
    }
    case Enrollment::VerifySearch: {
        const auto reply = sensor_.search(1, wait_budget(kSearchWaitMs));
        if (reply.code == SensorCode::Ok && reply.slot == candidate_.slot) enrollment_ = Enrollment::Commit;
        else finish_enrollment(false, "store_uncertain");
        break;
    }
    case Enrollment::Commit: {
        auto next = registry_;
        const auto committed = next.add(candidate_) == RegistryResult::Ok
                                   ? store_.commit(candidate_.slot) : StoreResult::Corrupt;
        const bool expired = wait_budget(kShortWaitMs) == 0;
        if (committed == StoreResult::Ok && !expired) {
            registry_ = std::move(next);
            status_.quarantined.reset(candidate_.slot);
            finish_enrollment(true, "enrolled");
        } else {
            quarantine(candidate_.slot);
            status_.message = expired ? "timeout" : "storage_failed";
            // Старый uiN мог исчезнуть. До разрушительного отката нужен новый надёжный маркер.
            if (store_.quarantine(candidate_.slot) != StoreResult::Ok) {
                // Без маркера сохраняем шаблон: после перезагрузки возможен целостный committed.
                finish_enrollment(false, "commit_indeterminate");
            } else if (wait_budget(kShortWaitMs) == 0) {
                finish_enrollment(false, "timeout");
            } else enrollment_ = Enrollment::Rollback;
        }
        break;
    }
    case Enrollment::Rollback: {
        const auto reply = sensor_.erase(candidate_.slot, wait_budget(kMutationWaitMs));
        if (reply.code == SensorCode::Ok) {
            occupied_.reset(candidate_.slot);
            enrollment_ = Enrollment::Discard;
        } else enrollment_ = Enrollment::RollbackIndex;
        break;
    }
    case Enrollment::RollbackIndex: {
        const auto reply = sensor_.index(wait_budget(kShortWaitMs));
        if (reply.code == SensorCode::Ok && !reply.occupied.test(candidate_.slot)) {
            occupied_.reset(candidate_.slot);
            enrollment_ = Enrollment::Discard;
        } else finish_enrollment(false, "rollback_uncertain");
        break;
    }
    case Enrollment::Discard:
        if (removed(store_.commit_delete(candidate_.slot))) {
            metadata_.reset(candidate_.slot);
            status_.quarantined.reset(candidate_.slot);
            staged_ = false;
            store_attempted_ = false;
            finish_enrollment(false, status_.message);
        } else {
            quarantine(candidate_.slot);
            finish_enrollment(false, "storage_failed");
        }
        break;
    }
}

void FingerprintController::reset_gesture()
{
    gesture_count_ = 0;
    local_enrollment_pending_ = false;
}

void FingerprintController::match(uint16_t slot)
{
    status_.last_match_slot = slot;
    const auto user = registry_.find(slot);
    if (!user || !user->active || status_.quarantined.test(slot)) {
        status_.last_access = "denied";
        reset_gesture();
        rejected_match(slot);
        signal_ = FingerprintSignal::Failure;
        return;
    }
    const auto now = clock_.now_ms();
    if (user->role == Role::Master) {
        if (!gesture_count_ || gesture_slot_ != slot || now - gesture_started_ms_ >= kCooldownMs) {
            gesture_slot_ = slot;
            gesture_started_ms_ = now;
            gesture_count_ = 1;
        } else ++gesture_count_;
        if (gesture_count_ == 3) local_enrollment_pending_ = true;
    } else reset_gesture();

    publish(AuditType::Access, AuditResultCode::Granted, slot, user->name);

    if (pulse_started_ && (now < pulse_started_ms_ || now - pulse_started_ms_ < kCooldownMs)) {
        status_.last_access = "cooldown";
        publish(AuditType::Gate, AuditResultCode::Rejected, slot, user->name);
        signal_ = FingerprintSignal::Success;
        return;
    }
    const auto pulse = gate_.pulse();
    if (pulse.accepted) {
        pulse_started_ = true;
        pulse_started_ms_ = pulse.started_ms;
        status_.last_access = "granted";
        publish(AuditType::Gate, AuditResultCode::Granted, slot, user->name);
        signal_ = FingerprintSignal::Success;
    } else {
        status_.last_access = "actuator_rejected";
        publish(AuditType::Gate, AuditResultCode::Rejected, slot, user->name);
        signal_ = FingerprintSignal::Failure;
        rejected_match(0);
    }
}

void FingerprintController::recognition_tick()
{
    switch (recognition_) {
    case Recognition::Idle:
        if (stable_touch_ && raw_touch_ && armed_) {
            armed_ = false;
            recognition_ = Recognition::Capture;
        }
        break;
    case Recognition::Capture:
        if (sensor_.capture(kShortWaitMs).code == SensorCode::Ok) {
            recognition_ = Recognition::Convert;
            break;
        }
        recognition_ = Recognition::Idle;
        status_.last_access = "capture_failed";
        reset_gesture();
        signal_ = FingerprintSignal::Failure;
        rejected_match(0);
        break;
    case Recognition::Convert:
        if (sensor_.convert(1, kShortWaitMs).code == SensorCode::Ok) {
            recognition_ = Recognition::Search;
            break;
        }
        recognition_ = Recognition::Idle;
        status_.last_access = "convert_failed";
        reset_gesture();
        signal_ = FingerprintSignal::Failure;
        break;
    case Recognition::Search: {
        const auto reply = sensor_.search(1, kSearchWaitMs);
        recognition_ = Recognition::Idle;
        if (reply.code == SensorCode::Ok && reply.slot < UserRegistry::kSlotCount) match(reply.slot);
        else {
            status_.last_access = reply.code == SensorCode::NotFound ? "not_found" : "search_failed";
            reset_gesture();
            rejected_match(reply.code == SensorCode::Ok ? reply.slot : 0);
            signal_ = FingerprintSignal::Failure;
        }
        break;
    }
    }
}

void FingerprintController::tick(bool touch_active)
{
    const auto now = clock_.now_ms();
    if (raw_touch_ != touch_active) {
        raw_touch_ = touch_active;
        touch_changed_ms_ = now;
        release_known_ = false;
    }
    if (now - touch_changed_ms_ >= kDebounceMs) {
        if (stable_touch_ != raw_touch_) {
            stable_touch_ = raw_touch_;
            if (!stable_touch_) {
                armed_ = true;
            }
        }
        if (!raw_touch_) release_known_ = true;
    }
    if (!status_.ready) {
        if (!initialized_ || now - last_initialize_ms_ >= kRetryMs) initialize();
        return;
    }
    if (status_.enrolling) {
        enrollment_tick();
        return;
    }
    if (local_enrollment_pending_ && release_known_ && !stable_touch_ && !raw_touch_) {
        // Локальные идентификаторы отделены старшим битом от идентификаторов HTTP.
        local_operation_id_ = ((local_operation_id_ + 1) | kLocalIdBit);
        const auto result = start_enrollment({}, local_operation_id_, AuditSource::Fingerprint);
        if (result != "ok") {
            reset_gesture();
            status_.message = result;
            signal_ = FingerprintSignal::Failure;
        }
        return;
    }
    recognition_tick();
}

FingerprintSnapshot FingerprintController::snapshot() const
{
    auto result = status_;
    for (uint16_t slot = 0; slot < UserRegistry::kSlotCount; ++slot) {
        const auto user = registry_.find(slot);
        if (user) result.users.push_back(*user);
    }
    if (status_.enrolling) {
        switch (enrollment_) {
        case Enrollment::Release: result.enrollment_state = "remove_finger"; break;
        case Enrollment::Touch: result.enrollment_state = "place_finger"; break;
        case Enrollment::Capture: result.enrollment_state = "capture"; break;
        case Enrollment::Convert: result.enrollment_state = "convert"; break;
        case Enrollment::Duplicate: result.enrollment_state = "duplicate_check"; break;
        case Enrollment::Create: result.enrollment_state = "create_model"; break;
        case Enrollment::Stage: result.enrollment_state = "stage"; break;
        case Enrollment::Store: result.enrollment_state = "store"; break;
        case Enrollment::VerifyIndex: result.enrollment_state = "verify_index"; break;
        case Enrollment::VerifySearch: result.enrollment_state = "verify_search"; break;
        case Enrollment::Commit: result.enrollment_state = "commit"; break;
        case Enrollment::Rollback: result.enrollment_state = "rollback"; break;
        case Enrollment::RollbackIndex: result.enrollment_state = "rollback_index"; break;
        case Enrollment::Discard: result.enrollment_state = "discard"; break;
        case Enrollment::Idle: break;
        }
    }
    return result;
}

FingerprintSignal FingerprintController::take_signal()
{
    const auto result = signal_;
    signal_ = FingerprintSignal::None;
    return result;
}

}
