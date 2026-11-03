#include "user_store.hpp"

namespace fg {
namespace {
constexpr uint8_t kVersion = 1;
constexpr uint8_t kPendingAdd = 1;
constexpr uint8_t kCommitted = 2;
constexpr uint8_t kPendingDelete = 3;
constexpr uint8_t kPendingUpdate = 4;

std::string intent_key(uint16_t slot) { return "ui" + std::to_string(slot); }
std::string quarantine_key(uint16_t slot) { return "uq" + std::to_string(slot); }

StoreResult erase_confirmed(KeyValueStore& storage, const std::string& key)
{
    const auto result = storage.erase(key);
    if (result == StoreResult::Ok || result == StoreResult::NotFound) return StoreResult::Ok;
    std::vector<uint8_t> bytes;
    return storage.get(key, &bytes) == StoreResult::NotFound ? StoreResult::Ok : result;
}

std::vector<uint8_t> encode(const User& user, uint8_t state)
{
    std::vector<uint8_t> bytes = {kVersion, state, static_cast<uint8_t>(user.slot >> 8),
                                  static_cast<uint8_t>(user.slot), static_cast<uint8_t>(user.role),
                                  static_cast<uint8_t>(user.active), static_cast<uint8_t>(user.name.size())};
    bytes.insert(bytes.end(), user.name.begin(), user.name.end());
    return bytes;
}

bool decode(const std::vector<uint8_t>& bytes, User* user, uint8_t* state)
{
    if (bytes.size() < 7 || bytes[0] != kVersion || bytes.size() != 7U + bytes[6] || bytes[4] > 1 || bytes[5] > 1) {
        return false;
    }
    user->slot = static_cast<uint16_t>(bytes[2] << 8) | bytes[3];
    user->role = static_cast<Role>(bytes[4]);
    user->active = bytes[5] != 0;
    user->name.assign(bytes.begin() + 7, bytes.end());
    *state = bytes[1];
    return *state >= kPendingAdd && *state <= kPendingUpdate;
}
}

StoreResult MemoryKeyValueStore::get(const std::string& key, std::vector<uint8_t>* value) const
{
    const auto item = values_.find(key);
    if (item == values_.end()) return StoreResult::NotFound;
    *value = item->second;
    return StoreResult::Ok;
}
StoreResult MemoryKeyValueStore::put(const std::string& key, const std::vector<uint8_t>& value) { values_[key] = value; return StoreResult::Ok; }
StoreResult MemoryKeyValueStore::erase(const std::string& key) { return values_.erase(key) ? StoreResult::Ok : StoreResult::NotFound; }

std::string UserStore::key(uint16_t slot) { return "u" + std::to_string(slot); }

StoreResult UserStore::stage(const User& user) { return storage_.put(key(user.slot), encode(user, kPendingAdd)); }

StoreResult UserStore::commit(uint16_t slot)
{
    std::vector<uint8_t> bytes;
    const StoreResult result = storage_.get(key(slot), &bytes);
    if (result != StoreResult::Ok) return result;
    User user; uint8_t state;
    if (!decode(bytes, &user, &state) || state != kPendingAdd || user.slot != slot) return StoreResult::Corrupt;
    // Отдельное намерение переживает неоднозначную запись committed и неудачный откат.
    const auto intent = storage_.put(intent_key(slot), bytes);
    if (intent != StoreResult::Ok) return intent;
    const auto committed = storage_.put(key(slot), encode(user, kCommitted));
    if (committed != StoreResult::Ok) return committed;
    return erase_confirmed(storage_, intent_key(slot));
}

StoreResult UserStore::stage_delete(uint16_t slot)
{
    std::vector<uint8_t> bytes;
    const auto guard = storage_.get(quarantine_key(slot), &bytes);
    if (guard != StoreResult::NotFound) return guard == StoreResult::Ok ? StoreResult::Corrupt : guard;
    const auto intent = storage_.get(intent_key(slot), &bytes);
    if (intent != StoreResult::NotFound) return intent == StoreResult::Ok ? StoreResult::Corrupt : intent;
    const StoreResult result = storage_.get(key(slot), &bytes);
    if (result != StoreResult::Ok) return result;
    User user; uint8_t state;
    if (!decode(bytes, &user, &state) || state != kCommitted || user.slot != slot) return StoreResult::Corrupt;
    return storage_.put(key(slot), encode(user, kPendingDelete));
}

StoreResult UserStore::commit_delete(uint16_t slot)
{
    const auto result = erase_confirmed(storage_, key(slot));
    if (result != StoreResult::Ok) return result;
    const auto intent = erase_confirmed(storage_, intent_key(slot));
    if (intent != StoreResult::Ok) return intent;
    return erase_confirmed(storage_, quarantine_key(slot));
}

StoreResult UserStore::update(const User& user)
{
    UserRegistry validation;
    if (validation.add(user) != RegistryResult::Ok ||
        (user.role != Role::User && user.role != Role::Master)) return StoreResult::Corrupt;
    std::vector<uint8_t> bytes;
    const auto guard = storage_.get(quarantine_key(user.slot), &bytes);
    if (guard != StoreResult::NotFound) return guard == StoreResult::Ok ? StoreResult::Corrupt : guard;
    const auto intent = storage_.get(intent_key(user.slot), &bytes);
    if (intent != StoreResult::NotFound) return intent == StoreResult::Ok ? StoreResult::Corrupt : intent;
    const auto result = storage_.get(key(user.slot), &bytes);
    if (result != StoreResult::Ok) return result;
    User previous; uint8_t state;
    if (!decode(bytes, &previous, &state) || state != kCommitted || previous.slot != user.slot)
        return StoreResult::Corrupt;
    const auto staged = storage_.put(intent_key(user.slot), encode(user, kPendingUpdate));
    if (staged != StoreResult::Ok) return staged;
    const auto committed = storage_.put(key(user.slot), encode(user, kCommitted));
    if (committed != StoreResult::Ok) return committed;
    return erase_confirmed(storage_, intent_key(user.slot));
}

StoreResult UserStore::quarantine(uint16_t slot)
{
    if (slot >= UserRegistry::kSlotCount) return StoreResult::Corrupt;
    const std::vector<uint8_t> marker = {kVersion, static_cast<uint8_t>(slot >> 8), static_cast<uint8_t>(slot)};
    const auto result = storage_.put(quarantine_key(slot), marker);
    if (result == StoreResult::Ok) return result;
    std::vector<uint8_t> observed;
    // Потерянное подтверждение записи допустимо только при доказанном наличии маркера.
    if (storage_.get(quarantine_key(slot), &observed) == StoreResult::Ok && observed == marker)
        return StoreResult::Ok;
    return StoreResult::Failed;
}

StoreSnapshot UserStore::load() const
{
    StoreSnapshot snapshot;
    for (uint16_t slot = 0; slot < UserRegistry::kSlotCount; ++slot) {
        std::vector<uint8_t> bytes;
        const bool guarded = storage_.get(quarantine_key(slot), &bytes) != StoreResult::NotFound;
        if (guarded) {
            snapshot.metadata.set(slot);
            snapshot.quarantined.set(slot);
        }
        bytes.clear();
        const auto intent = storage_.get(intent_key(slot), &bytes);
        if (intent != StoreResult::NotFound) {
            snapshot.metadata.set(slot);
            snapshot.quarantined.set(slot);
            User user; uint8_t state;
            UserRegistry validation;
            if (intent == StoreResult::Ok && decode(bytes, &user, &state) && user.slot == slot &&
                validation.add(user) == RegistryResult::Ok) {
                if (state == kPendingAdd) snapshot.pending_add.set(slot);
                if (state == kPendingUpdate) snapshot.pending_update.set(slot);
            }
            continue;
        }
        bytes.clear();
        const auto result = storage_.get(key(slot), &bytes);
        if (result == StoreResult::NotFound) continue;
        snapshot.metadata.set(slot);
        User user; uint8_t state;
        UserRegistry validation;
        if (result != StoreResult::Ok || !decode(bytes, &user, &state) || user.slot != slot ||
            validation.add(user) != RegistryResult::Ok) {
            snapshot.quarantined.set(slot);
            continue;
        }
        if (state == kPendingAdd) snapshot.pending_add.set(slot);
        if (state == kPendingDelete) snapshot.pending_delete.set(slot);
        if (guarded || state != kCommitted || snapshot.registry.add(user) != RegistryResult::Ok)
            snapshot.quarantined.set(slot);
    }
    return snapshot;
}

}
