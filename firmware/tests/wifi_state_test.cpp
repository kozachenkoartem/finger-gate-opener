#include "wifi_lifecycle.hpp"
#include "wifi_event_gate.hpp"
#include "network_requests.hpp"

#include <cstdlib>
#include <iostream>
#include <vector>

namespace {
void require(bool value, const char* message)
{
    if (!value) { std::cerr << message << '\n'; std::exit(EXIT_FAILURE); }
}

class Port final : public fg::NetworkPort {
public:
    bool open_ap(const std::string& password) override { ++opens; ap_password = password; return open_ok; }
    bool close_ap() override { ++closes; return close_ok; }
    bool connect(const fg::WifiCredentials& credentials, uint32_t attempt) override
    { targets.push_back(credentials.ssid); current = attempt; return connect_ok; }
    bool disconnect() override { ++disconnects; return true; }
    std::vector<std::string> targets;
    std::string ap_password;
    uint32_t current = 0;
    int opens = 0, closes = 0, disconnects = 0;
    bool open_ok = true, close_ok = true, connect_ok = true;
};

void test_switch_failure_returns_to_old_network()
{
    fg::MemoryKeyValueStore storage;
    require(fg::ConfigStore(storage).save_wifi({"old", "old-password"}) == fg::StoreResult::Ok, "initial credentials saved");
    Port port;
    fg::WifiLifecycle wifi(storage, port);
    require(wifi.initialize(0), "lifecycle initializes");
    wifi.got_ip(port.current, "10.0.0.2", 100);
    require(wifi.open_recovery(200) == fg::NetworkResult::Ok, "recovery AP opens while STA stays connected");
    const auto expiry = wifi.status().ap_deadline_ms;
    require(wifi.open_recovery(300) == fg::NetworkResult::Busy && wifi.status().ap_deadline_ms == expiry,
            "repeated requests cannot extend recovery window");
    const uint32_t old_attempt = port.current;
    require(wifi.configure_wifi({"new", "bad-password"}, 400) == fg::NetworkResult::Ok, "trial accepted");
    wifi.got_ip(old_attempt, "10.0.0.2", 401);
    require(wifi.status().trial && !wifi.status().connected, "old IP cannot accept candidate credentials");
    wifi.disconnected(port.current, 500);
    require(port.targets.back() == "old", "failed candidate restores old network");
    wifi.got_ip(port.current, "10.0.0.2", 600);
    require(wifi.status().connected && wifi.status().last_trial == "failed" && wifi.status().ap_active,
            "failure is visible after restoration and AP remains usable");
    require(wifi.status().indication == fg::ProvisioningIndication::Failed, "fast fallback cannot erase the red failure indication");
    wifi.poll(1700);
    require(wifi.status().indication == fg::ProvisioningIndication::AccessPoint, "failure flashes return to the recovery AP pulse");
    fg::WifiCredentials saved;
    require(fg::ConfigStore(storage).load_wifi(&saved) == fg::StoreResult::Ok && saved.ssid == "old",
            "bad candidate never replaces saved credentials");
}

void test_success_ack_and_reboot()
{
    fg::MemoryKeyValueStore storage;
    fg::ConfigStore(storage).save_wifi({"old", "old-password"});
    Port port;
    fg::WifiLifecycle wifi(storage, port);
    require(wifi.initialize(0), "boot succeeds");
    wifi.got_ip(port.current, "10.0.0.2", 10);
    wifi.open_recovery(20);
    require(wifi.configure_wifi({"new", "new-password"}, 30) == fg::NetworkResult::Ok, "new target accepted");
    wifi.got_ip(port.current, "10.1.0.3", 40);
    require(wifi.status().connected && wifi.status().last_trial == "success", "new IP commits successful trial");
    require(wifi.acknowledge(50) == fg::NetworkResult::Ok, "success can be acknowledged");
    wifi.poll(549);
    require(port.closes == 0, "AP survives acknowledgement response grace period");
    wifi.poll(550);
    require(!wifi.status().ap_active && wifi.status().connected && port.closes == 1,
            "ack closes AP without disconnecting station");
    Port reboot_port;
    fg::WifiLifecycle reboot(storage, reboot_port);
    require(reboot.initialize(0) && reboot_port.targets.back() == "new" && reboot_port.opens == 0,
            "reboot uses new accepted credentials without AP");
}

void test_expiry_timeout_and_regular_reconnect()
{
    fg::MemoryKeyValueStore storage;
    fg::ConfigStore(storage).save_wifi({"old", "old-password"});
    Port port;
    fg::WifiLifecycle wifi(storage, port);
    wifi.initialize(0);
    wifi.got_ip(port.current, "10.0.0.2", 10);
    wifi.disconnected(port.current, 20);
    wifi.poll(5019);
    require(port.targets.size() == 1 && port.opens == 0, "ordinary loss waits before retry and never opens AP");
    wifi.poll(5020);
    require(port.targets.size() == 2 && port.opens == 0, "saved station reconnects after five seconds");
    wifi.got_ip(port.current, "10.0.0.2", 5030);
    wifi.open_recovery(6000);
    wifi.configure_wifi({"new", "bad-password"}, 300000);
    port.close_ok = false;
    wifi.poll(306000);
    require(port.targets.back() == "old" && wifi.status().ap_active && wifi.status().ap_closing,
            "expiry cancels trial safely and visibly retries failed AP close");
    port.close_ok = true;
    wifi.poll(307000);
    require(!wifi.status().ap_active, "expiry closes recovery AP even while old station reconnects");
}

void test_first_boot_password_and_driver_errors()
{
    fg::MemoryKeyValueStore storage;
    Port port;
    fg::WifiLifecycle wifi(storage, port);
    require(wifi.initialize(0) && port.opens == 1 && port.ap_password == "fingergate", "first boot AP uses default password");
    require(wifi.set_ap_password("individual-123") == fg::NetworkResult::Busy, "password change cannot disconnect active AP clients");
    wifi.poll(600000);
    require(wifi.status().ap_active, "initial setup AP has no recovery expiry before first successful setup");
    wifi.configure_wifi({"first", "password"}, 600001);
    wifi.poll(630001);
    require(wifi.status().last_trial == "failed" && wifi.status().ap_active, "first connection timeout stays observable in AP");

    fg::MemoryKeyValueStore saved;
    fg::ConfigStore(saved).save_wifi({"old", "password"});
    Port failed;
    failed.connect_ok = false;
    fg::WifiLifecycle reconnect(saved, failed);
    require(reconnect.initialize(0), "recoverable initial connect error does not disable lifecycle polling");
    failed.connect_ok = true;
    reconnect.poll(5000);
    reconnect.got_ip(failed.current, "10.0.0.2", 5010);
    require(reconnect.set_ap_password("individual-123") == fg::NetworkResult::Ok, "new AP password persists while AP is off");
    require(reconnect.open_recovery(5020) == fg::NetworkResult::Ok && failed.ap_password == "individual-123", "recovery uses persisted individual password");
    reconnect.event_loss(5030);
    require(!reconnect.status().connected && failed.targets.back() == "old", "event loss cannot claim successful station connection");
}

void test_actual_event_boundary_for_same_ssid()
{
    fg::WifiEventGate gate;
    const std::array<uint8_t, 6> bssid{1,2,3,4,5,6};
    gate.begin(1, "same", 0);
    require(!gate.associated(1, "same", bssid), "association is ignored until old disconnect boundary");
    require(gate.disconnected(2, "old", bssid) == fg::LinkLoss::Boundary, "intentional disconnect opens handover boundary");
    gate.started(5);
    require(!gate.associated(4, "same", bssid), "previously queued same-SSID association is stale");
    require(!gate.ip(6, bssid), "IP without fresh matching association is ignored");
    require(gate.associated(7, "same", bssid), "fresh matching association accepted");
    require(gate.ip(8, bssid) == 1, "IP tied to actual new association");
    gate.begin(2, "same", 9);
    require(!gate.ip(10, bssid), "same-SSID password retry invalidates old IP eligibility");
    require(gate.disconnected(11, "same", bssid) == fg::LinkLoss::Boundary, "fallback/retry waits for disconnect too");
    gate.started(12);
    require(!gate.associated(13, "different", bssid), "wrong network association rejected");
    require(gate.associated(14, "same", bssid) && gate.ip(15, bssid) == 2, "fresh retry belongs to new attempt");
}

void test_request_admission_before_response_and_owner_revalidation()
{
    fg::NetworkRequests requests;
    fg::WifiStatus status;
    status.state = "connected";
    status.connected = true;
    const auto first = requests.reserve(fg::NetworkOperation::Recovery, {}, {}, status);
    require(first != 0 && !requests.take(100000), "reserved command cannot run before HTTP response");
    require(!requests.reserve(fg::NetworkOperation::ApPassword, {}, "individual-123", status), "full request slot rejected before sending 202");
    requests.finish_response(first, false, 0);
    require(!requests.take(100000) && requests.last_result() == "response_failed", "failed HTTP response cancels side effect");
    const auto second = requests.reserve(fg::NetworkOperation::Recovery, {}, {}, status);
    requests.finish_response(second, true, 100);
    require(!requests.take(599) && requests.take(600)->id == second, "activation waits for response grace period");
    status.ap_active = true;
    require(!requests.reserve(fg::NetworkOperation::ApPassword, {}, "individual-123", status), "AP password updates rejected while clients may use AP");
    fg::MemoryKeyValueStore storage;
    Port port;
    fg::WifiLifecycle wifi(storage, port);
    wifi.initialize(0);
    require(wifi.set_ap_password("individual-123") == fg::NetworkResult::Busy, "owner revalidates AP state after command was reserved");
    require(!requests.reserve(fg::NetworkOperation::Configure, {std::string(33, 'x'), "password"}, {}, status), "oversized SSID cannot overflow queued request");
}

void test_late_ip_and_overflow_cannot_commit_candidate()
{
    fg::MemoryKeyValueStore storage;
    fg::ConfigStore(storage).save_wifi({"old", "password"});
    Port port;
    fg::WifiLifecycle wifi(storage, port);
    wifi.initialize(0);
    wifi.got_ip(port.current, "10.0.0.2", 10);
    wifi.open_recovery(20);
    wifi.configure_wifi({"new", "password"}, 30);
    wifi.got_ip(port.current, "10.1.0.3", 30030);
    require(port.targets.back() == "old" && wifi.status().last_trial == "failed", "IP after absolute attempt deadline triggers fallback instead of persistence");
    wifi.got_ip(port.current, "10.0.0.2", 30040);
    wifi.configure_wifi({"new", "password"}, 30050);
    const auto candidate_attempt = port.current;
    wifi.event_loss(30060);
    wifi.got_ip(candidate_attempt, "10.1.0.3", 30070);
    require(!wifi.status().connected && port.targets.back() == "old", "event loss invalidates queued candidate success");
    fg::WifiCredentials saved;
    require(fg::ConfigStore(storage).load_wifi(&saved) == fg::StoreResult::Ok && saved.ssid == "old", "late IP and overflow preserve accepted credentials");
}
}

int main()
{
    test_switch_failure_returns_to_old_network();
    test_success_ack_and_reboot();
    test_expiry_timeout_and_regular_reconnect();
    test_first_boot_password_and_driver_errors();
    test_actual_event_boundary_for_same_ssid();
    test_request_admission_before_response_and_owner_revalidation();
    test_late_ip_and_overflow_cannot_commit_candidate();
}
