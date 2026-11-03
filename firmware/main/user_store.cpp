#include "user_store.hpp"

namespace fg {
namespace {
constexpr uint8_t kVersion = 1;
constexpr uint8_t kPendingAdd = 1;
constexpr uint8_t kCommitted = 2;
constexpr uint8_t kPendingDelete = 3;

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
    return *state >= kPendingAdd && *state <= kPendingDelete;
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
    return storage_.put(key(slot), encode(user, kCommitted));
}

StoreResult UserStore::stage_delete(uint16_t slot)
{
    std::vector<uint8_t> bytes;
    const StoreResult result = storage_.get(key(slot), &bytes);
    if (result != StoreResult::Ok) return result;
    User user; uint8_t state;
    if (!decode(bytes, &user, &state) || state != kCommitted || user.slot != slot) return StoreResult::Corrupt;
    return storage_.put(key(slot), encode(user, kPendingDelete));
}

StoreResult UserStore::commit_delete(uint16_t slot) { return storage_.erase(key(slot)); }

StoreSnapshot UserStore::load() const
{
    StoreSnapshot snapshot;
    for (uint16_t slot = 0; slot < UserRegistry::kSlotCount; ++slot) {
        std::vector<uint8_t> bytes;
        if (storage_.get(key(slot), &bytes) == StoreResult::NotFound) continue;
        User user; uint8_t state;
        if (!decode(bytes, &user, &state) || user.slot != slot || state != kCommitted ||
            snapshot.registry.add(user) != RegistryResult::Ok) {
            snapshot.quarantined.set(slot);
        }
    }
    return snapshot;
}

}
