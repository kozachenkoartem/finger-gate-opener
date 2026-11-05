#pragma once

#include <array>
#include <atomic>
#include <mutex>
#include <string>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "fingerprint_controller.hpp"
#include "gate_actuator.hpp"
#include "indicator.hpp"
#include "r558s_driver.hpp"
#include "hub_auth.hpp"

namespace fg {
struct CommandReceipt { uint32_t id = 0; std::string result; };
class FingerprintTask {
public:
    FingerprintTask(KeyValueStore& storage, AuditPublisher& audit, HubAuth& hub_auth, HubCommandLedger& hub_ledger)
        : storage_(storage), audit_(audit), hub_auth_(hub_auth), hub_ledger_(hub_ledger) {}
    void start();
    void set_provisioning(ProvisioningIndicatorState state);
    CommandReceipt submit(const FingerprintCommand& command);
    std::string snapshot_json();

private:
    struct QueuedCommand {
        uint32_t id;
        FingerprintCommandType type;
        uint16_t slot;
        char name[65];
        Role role;
        uint32_t operation_id;
        AuditSource source;
        char request_id[65];
    };
    static void task_entry(void* context);
    void run();
    void publish(const FingerprintSnapshot& snapshot);

    KeyValueStore& storage_;
    AuditPublisher& audit_;
    HubAuth& hub_auth_;
    HubCommandLedger& hub_ledger_;
    QueueHandle_t indication_queue_ = nullptr;
    QueueHandle_t command_queue_ = nullptr;
    std::atomic<uint32_t> next_command_id_{1};
    std::mutex snapshot_mutex_;
    std::string snapshot_json_ = "{\"ready\":false,\"users\":[],\"commands\":[],\"quarantined\":[],\"enrollment\":{\"active\":false,\"state\":\"initializing\",\"id\":0}}";
    std::array<CommandReceipt, 8> receipts_{};
    size_t receipt_index_ = 0;
    GateActuator gate_;
    r558s::Driver driver_{UART_NUM_1, 5, 4, 57600};
};
}
