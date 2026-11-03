#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>

namespace fg {

enum class Role : uint8_t {
    User,
    Master,
};

struct User {
    uint16_t slot = 0;
    std::string name;
    Role role = Role::User;
    bool active = true;
};

enum class RegistryResult : uint8_t {
    Ok,
    InvalidSlot,
    InvalidName,
    SlotAlreadyExists,
    MasterLimitReached,
    NotFound,
};

enum class AccessDecision : uint8_t {
    Grant,
    DenyUnknown,
    DenyInactive,
};

class UserRegistry {
public:
    static constexpr uint16_t kSlotCount = 100;
    static constexpr uint8_t kMasterLimit = 2;

    RegistryResult add(User user);
    RegistryResult rename(uint16_t slot, std::string name);
    RegistryResult set_role(uint16_t slot, Role role);
    RegistryResult remove(uint16_t slot);
    std::optional<User> find(uint16_t slot) const;
    AccessDecision access_decision(uint16_t slot) const;

private:
    static bool is_valid_name(const std::string& name);
    uint8_t active_master_count() const;

    std::array<std::optional<User>, kSlotCount> users_;
};

}
