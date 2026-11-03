#include <cstdlib>
#include <iostream>

#include "config_store.hpp"
#include "user_store.hpp"

namespace {

void require(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}

class UnavailableStore final : public fg::KeyValueStore {
public:
    fg::StoreResult get(const std::string&, std::vector<uint8_t>*) const override { return fg::StoreResult::Failed; }
    fg::StoreResult put(const std::string&, const std::vector<uint8_t>&) override { return fg::StoreResult::Failed; }
    fg::StoreResult erase(const std::string&) override { return fg::StoreResult::Failed; }
};

class FaultStore final : public fg::KeyValueStore {
public:
    fg::StoreResult get(const std::string& key, std::vector<uint8_t>* value) const override
    { return key == failed_read ? fg::StoreResult::Failed : memory.get(key, value); }
    fg::StoreResult put(const std::string& key, const std::vector<uint8_t>& value) override
    {
        if (key == failed_put && !persist_failure) return fg::StoreResult::Failed;
        const auto result = memory.put(key, value);
        return key == failed_put ? fg::StoreResult::Failed : result;
    }
    fg::StoreResult erase(const std::string& key) override
    {
        if (key == failed_erase && !persist_failure) return fg::StoreResult::Failed;
        const auto result = memory.erase(key);
        return key == failed_erase ? fg::StoreResult::Failed : result;
    }
    fg::MemoryKeyValueStore memory;
    std::string failed_read, failed_put, failed_erase;
    bool persist_failure = false;
};

void test_credentials_round_trip()
{
    fg::MemoryKeyValueStore storage;
    fg::ConfigStore config(storage);
    const fg::WifiCredentials saved{"Office Wi-Fi", "correct horse battery staple"};
    fg::WifiCredentials loaded;

    require(config.save_wifi(saved) == fg::StoreResult::Ok, "credentials must persist");
    require(config.load_wifi(&loaded) == fg::StoreResult::Ok, "persisted credentials must load");
    require(loaded.ssid == saved.ssid && loaded.password == saved.password, "loaded credentials must match saved values");
}

void test_unavailable_storage_fails_closed()
{
    UnavailableStore storage;
    fg::ConfigStore config(storage);
    fg::WifiCredentials loaded;

    require(config.save_wifi({"Office", "secret"}) == fg::StoreResult::Failed, "unavailable storage must reject credentials");
    require(config.load_wifi(&loaded) == fg::StoreResult::Failed, "unavailable storage must not invent credentials");
    require(!fg::should_start_provisioning(fg::StoreResult::Failed), "storage failure must not open an unsecured AP");
}

void test_only_first_boot_opens_provisioning()
{
    require(fg::should_start_provisioning(fg::StoreResult::NotFound), "missing credentials must open provisioning");
    require(!fg::should_start_provisioning(fg::StoreResult::Ok), "saved credentials must reconnect without an AP");
}

void test_individual_ap_password_and_validation()
{
    fg::MemoryKeyValueStore storage;
    fg::ConfigStore config(storage);
    std::string password;
    bool custom = true;
    require(config.load_ap_password(&password, &custom) == fg::StoreResult::Ok && password == "fingergate" && !custom,
            "missing AP password uses developer default");
    require(config.save_ap_password("private-ap-123") == fg::StoreResult::Ok, "individual AP password persists");
    require(config.load_ap_password(&password, &custom) == fg::StoreResult::Ok && password == "private-ap-123" && custom,
            "AP password survives reloading config");
    for (const auto& invalid : {std::string("short"), std::string(64, 'a'), std::string("password\n"), std::string("null\0pass", 9)})
        require(config.save_ap_password(invalid) == fg::StoreResult::Corrupt, "invalid AP password rejected");
    storage.put("ap_password", {2, 'x'});
    require(config.load_ap_password(&password, &custom) == fg::StoreResult::Corrupt,
            "corrupt individual password never silently falls back to default");
}

void test_wifi_commit_fault_boundaries_and_reboot()
{
    for (const std::string key : {"wifi_rollback", "wifi"}) {
        FaultStore storage;
        fg::ConfigStore config(storage);
        require(config.save_wifi({"old", "old-password"}) == fg::StoreResult::Ok, "baseline saved");
        storage.failed_put = key;
        require(config.save_wifi({"new", "new-password"}) == fg::StoreResult::Failed, "failed commit is reported");
        storage.failed_put.clear();
        fg::WifiCredentials loaded;
        require(fg::ConfigStore(storage).load_wifi(&loaded) == fg::StoreResult::Ok && loaded.ssid == "old", "reboot preserves old network at each write boundary");
    }
    for (const bool persisted : {false, true}) {
        FaultStore storage;
        fg::ConfigStore config(storage);
        config.save_wifi({"old", "old-password"});
        storage.failed_erase = "wifi_rollback";
        storage.persist_failure = persisted;
        const auto result = config.save_wifi({"new", "new-password"});
        require(result == (persisted ? fg::StoreResult::Ok : fg::StoreResult::Failed), "guard removal needs acknowledged or read-back absence");
        storage.failed_erase.clear();
        fg::WifiCredentials loaded;
        require(config.load_wifi(&loaded) == fg::StoreResult::Ok && loaded.ssid == (persisted ? "new" : "old"), "boot agrees with reported finalization");
    }
    FaultStore interrupted;
    interrupted.memory.put("wifi", {3, 8, 'n','e','w','p','a','s','s','w','o','r','d'});
    interrupted.memory.put("wifi_rollback", {1, 0});
    fg::WifiCredentials loaded;
    require(fg::ConfigStore(interrupted).load_wifi(&loaded) == fg::StoreResult::NotFound, "interrupted first setup restores absence rather than accepting trial");
    interrupted.memory.put("wifi_rollback", {2, 0});
    require(fg::ConfigStore(interrupted).load_wifi(&loaded) == fg::StoreResult::Corrupt, "corrupt guard fails closed");
    interrupted.failed_read = "wifi_rollback";
    require(fg::ConfigStore(interrupted).load_wifi(&loaded) == fg::StoreResult::Failed, "unreadable guard is not treated as absent");
}

void test_failed_recovery_cannot_overwrite_old_guard()
{
    FaultStore storage;
    storage.memory.put("wifi", {3, 8, 'n','e','w','p','a','s','s','w','o','r','d'});
    const std::vector<uint8_t> guard{1, 1, 3, 8, 'o','l','d','p','a','s','s','w','o','r','d'};
    storage.memory.put("wifi_rollback", guard);
    storage.failed_put = "wifi";
    fg::ConfigStore config(storage);
    fg::WifiCredentials loaded;
    require(config.load_wifi(&loaded) == fg::StoreResult::Failed, "failed restoration stays unresolved");
    require(config.save_wifi({"third", "third-password"}) == fg::StoreResult::Failed, "new commit cannot replace unresolved recovery guard");
    std::vector<uint8_t> observed;
    require(storage.memory.get("wifi_rollback", &observed) == fg::StoreResult::Ok && observed == guard, "original guard remains intact");
    storage.failed_put.clear();
    require(config.load_wifi(&loaded) == fg::StoreResult::Ok && loaded.ssid == "old", "recovery is idempotent and succeeds after storage returns");
}

}

int main()
{
    test_credentials_round_trip();
    test_unavailable_storage_fails_closed();
    test_only_first_boot_opens_provisioning();
    test_individual_ap_password_and_validation();
    test_wifi_commit_fault_boundaries_and_reboot();
    test_failed_recovery_cannot_overwrite_old_guard();
    return EXIT_SUCCESS;
}
