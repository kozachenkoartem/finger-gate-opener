#include "finger_gate_model.hpp"

#include <cctype>

namespace fg {

RegistryResult UserRegistry::add(User user)
{
    if (user.slot >= kSlotCount) {
        return RegistryResult::InvalidSlot;
    }
    if (!is_valid_name(user.name)) {
        return RegistryResult::InvalidName;
    }
    if (users_[user.slot].has_value()) {
        return RegistryResult::SlotAlreadyExists;
    }
    if (user.active && user.role == Role::Master && active_master_count() >= kMasterLimit) {
        return RegistryResult::MasterLimitReached;
    }

    users_[user.slot] = std::move(user);
    return RegistryResult::Ok;
}

RegistryResult UserRegistry::rename(uint16_t slot, std::string name)
{
    if (slot >= kSlotCount) {
        return RegistryResult::InvalidSlot;
    }
    if (!is_valid_name(name)) {
        return RegistryResult::InvalidName;
    }
    if (!users_[slot].has_value()) {
        return RegistryResult::NotFound;
    }

    users_[slot]->name = std::move(name);
    return RegistryResult::Ok;
}

RegistryResult UserRegistry::set_role(uint16_t slot, Role role)
{
    if (slot >= kSlotCount) {
        return RegistryResult::InvalidSlot;
    }
    if (!users_[slot].has_value()) {
        return RegistryResult::NotFound;
    }
    if (users_[slot]->active && role == Role::Master && users_[slot]->role != Role::Master &&
        active_master_count() >= kMasterLimit) {
        return RegistryResult::MasterLimitReached;
    }

    users_[slot]->role = role;
    return RegistryResult::Ok;
}

RegistryResult UserRegistry::remove(uint16_t slot)
{
    if (slot >= kSlotCount) {
        return RegistryResult::InvalidSlot;
    }
    if (!users_[slot].has_value()) {
        return RegistryResult::NotFound;
    }

    users_[slot].reset();
    return RegistryResult::Ok;
}

std::optional<User> UserRegistry::find(uint16_t slot) const
{
    if (slot >= kSlotCount) {
        return std::nullopt;
    }
    return users_[slot];
}

AccessDecision UserRegistry::access_decision(uint16_t slot) const
{
    const std::optional<User> user = find(slot);
    if (!user.has_value()) {
        return AccessDecision::DenyUnknown;
    }
    return user->active ? AccessDecision::Grant : AccessDecision::DenyInactive;
}

bool UserRegistry::is_valid_name(const std::string& name)
{
    if (name.empty() || name.size() > 64) {
        return false;
    }

    for (const unsigned char character : name) {
        if (!std::isspace(character)) {
            return true;
        }
    }
    return false;
}

uint8_t UserRegistry::active_master_count() const
{
    uint8_t count = 0;
    for (const std::optional<User>& user : users_) {
        if (user.has_value() && user->active && user->role == Role::Master) {
            ++count;
        }
    }
    return count;
}

}
