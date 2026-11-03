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

namespace fg {
struct CommandReceipt { uint32_t id = 0; std::string result; };
class FingerprintTask {
public:
    explicit FingerprintTask(KeyValueStore& storage) : storage_(storage) {}
    void start();
    void set_provisioning(ProvisioningIndicatorState state);
    uint32_t submit(const FingerprintCommand& command);
    std::string snapshot_json();

private:
    struct QueuedCommand {
        uint32_t id;
        FingerprintCommandType type;
        uint16_t slot;
        char name[65];
        Role role;
        uint32_t operation_id;
    };
    static void task_entry(void* context);
    void run();
    void publish(const FingerprintSnapshot& snapshot);

    KeyValueStore& storage_;
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
