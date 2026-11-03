#pragma once

#include <bitset>
#include <map>
#include <string>
#include <vector>

#include "finger_gate_model.hpp"

namespace fg {

enum class StoreResult : uint8_t { Ok, NotFound, Corrupt, Failed };

class KeyValueStore {
public:
    virtual ~KeyValueStore() = default;
    virtual StoreResult get(const std::string& key, std::vector<uint8_t>* value) const = 0;
    virtual StoreResult put(const std::string& key, const std::vector<uint8_t>& value) = 0;
    virtual StoreResult erase(const std::string& key) = 0;
};

class MemoryKeyValueStore final : public KeyValueStore {
public:
    StoreResult get(const std::string& key, std::vector<uint8_t>* value) const override;
    StoreResult put(const std::string& key, const std::vector<uint8_t>& value) override;
    StoreResult erase(const std::string& key) override;

private:
    std::map<std::string, std::vector<uint8_t>> values_;
};

struct StoreSnapshot {
    UserRegistry registry;
    std::bitset<UserRegistry::kSlotCount> quarantined;
    std::bitset<UserRegistry::kSlotCount> metadata;
    std::bitset<UserRegistry::kSlotCount> pending_add;
    std::bitset<UserRegistry::kSlotCount> pending_delete;
    std::bitset<UserRegistry::kSlotCount> pending_update;
};

class UserStore {
public:
    explicit UserStore(KeyValueStore& storage) : storage_(storage) {}
    StoreResult stage(const User& user);
    StoreResult commit(uint16_t slot);
    StoreResult stage_delete(uint16_t slot);
    StoreResult commit_delete(uint16_t slot);
    StoreResult update(const User& user);
    // Ok означает подтверждённый постоянный запрет; шаблон и запись uN не меняются.
    // При Failed разрушительный откат запрещён: committed мог сохраниться без uiN.
    StoreResult quarantine(uint16_t slot);
    StoreSnapshot load() const;

private:
    static std::string key(uint16_t slot);
    KeyValueStore& storage_;
};

}
