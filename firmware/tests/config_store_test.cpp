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

}

int main()
{
    test_credentials_round_trip();
    test_unavailable_storage_fails_closed();
    test_only_first_boot_opens_provisioning();
    return EXIT_SUCCESS;
}
