#include <cstdlib>
#include <iostream>

#include "finger_gate_model.hpp"

namespace {

void require(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}

fg::User user(uint16_t slot, const char* name, fg::Role role = fg::Role::User, bool active = true)
{
    return {.slot = slot, .name = name, .role = role, .active = active};
}

void test_active_user_and_master_are_granted_access()
{
    fg::UserRegistry registry;
    require(registry.add(user(1, "Alice")) == fg::RegistryResult::Ok, "active User must be accepted");
    require(registry.add(user(2, "Bob", fg::Role::Master)) == fg::RegistryResult::Ok,
            "active Master must be accepted");

    require(registry.access_decision(1) == fg::AccessDecision::Grant,
            "active User must be allowed to open the gate");
    require(registry.access_decision(2) == fg::AccessDecision::Grant,
            "active Master must be allowed to open the gate");
}

void test_third_master_is_rejected()
{
    fg::UserRegistry registry;
    require(registry.add(user(1, "First", fg::Role::Master)) == fg::RegistryResult::Ok,
            "first Master must be accepted");
    require(registry.add(user(2, "Second", fg::Role::Master)) == fg::RegistryResult::Ok,
            "second Master must be accepted");
    require(registry.add(user(3, "Third", fg::Role::Master)) == fg::RegistryResult::MasterLimitReached,
            "third Master must be rejected");
    require(registry.set_role(3, fg::Role::Master) == fg::RegistryResult::NotFound,
            "role changes must not create an unregistered user");
}

void test_role_change_enforces_master_limit()
{
    fg::UserRegistry registry;
    require(registry.add(user(1, "First", fg::Role::Master)) == fg::RegistryResult::Ok,
            "first Master must be accepted");
    require(registry.add(user(2, "Second", fg::Role::Master)) == fg::RegistryResult::Ok,
            "second Master must be accepted");
    require(registry.add(user(3, "User")) == fg::RegistryResult::Ok, "User must be accepted");

    require(registry.set_role(3, fg::Role::Master) == fg::RegistryResult::MasterLimitReached,
            "promotion beyond two Masters must be rejected");
    require(registry.set_role(2, fg::Role::User) == fg::RegistryResult::Ok,
            "demoting a Master must be accepted");
    require(registry.set_role(3, fg::Role::Master) == fg::RegistryResult::Ok,
            "promotion must succeed after a Master is demoted");
}

void test_duplicate_slot_and_invalid_name_are_rejected()
{
    fg::UserRegistry registry;
    require(registry.add(user(1, "Alice")) == fg::RegistryResult::Ok, "first slot assignment must be accepted");
    require(registry.add(user(1, "Other")) == fg::RegistryResult::SlotAlreadyExists,
            "duplicate slots must be rejected");
    require(registry.add(user(2, "")) == fg::RegistryResult::InvalidName,
            "empty names must be rejected");
    require(registry.rename(1, "") == fg::RegistryResult::InvalidName,
            "renaming to an empty name must be rejected");
}

void test_inactive_and_unknown_records_are_denied()
{
    fg::UserRegistry registry;
    require(registry.add(user(1, "Inactive", fg::Role::User, false)) == fg::RegistryResult::Ok,
            "inactive records must remain representable for recovery");

    require(registry.access_decision(1) == fg::AccessDecision::DenyInactive,
            "inactive records must not open the gate");
    require(registry.access_decision(2) == fg::AccessDecision::DenyUnknown,
            "unknown slots must not open the gate");
}

void test_removing_user_revokes_access()
{
    fg::UserRegistry registry;
    require(registry.add(user(1, "Alice")) == fg::RegistryResult::Ok, "User must be accepted");
    require(registry.remove(1) == fg::RegistryResult::Ok, "registered User must be removable");
    require(registry.access_decision(1) == fg::AccessDecision::DenyUnknown,
            "removed User must not open the gate");
}

void test_new_user_defaults_to_user_role()
{
    fg::User candidate;
    candidate.slot = 4;
    candidate.name = "Default";

    require(candidate.role == fg::Role::User, "new local enrollment records must default to User role");
}

}

int main()
{
    test_active_user_and_master_are_granted_access();
    test_third_master_is_rejected();
    test_role_change_enforces_master_limit();
    test_duplicate_slot_and_invalid_name_are_rejected();
    test_inactive_and_unknown_records_are_denied();
    test_removing_user_revokes_access();
    test_new_user_defaults_to_user_role();
    return EXIT_SUCCESS;
}
