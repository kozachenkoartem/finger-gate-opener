#pragma once

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

#include "indicator.hpp"
#include "r558s_driver.hpp"

namespace fg {

class FingerprintTask {
public:
    void start();
    void set_provisioning(ProvisioningIndicatorState state);

private:
    static void task_entry(void* context);
    void run();

    QueueHandle_t indication_queue_ = nullptr;
    r558s::Driver driver_{UART_NUM_1, 5, 4, 57600};
};

}
