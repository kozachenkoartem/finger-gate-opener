#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "driver/uart.h"

namespace r558s {

enum class LedColor : uint8_t {
    Blue = 0x01,
    Green = 0x02,
    Red = 0x04,
    Yellow = 0x06,
};

enum class TransactionStatus {
    Success,
    SensorRejected,
    Timeout,
    InvalidResponse,
    WriteFailure,
};

struct TransactionResult {
    TransactionStatus status = TransactionStatus::InvalidResponse;
    uint8_t confirmation_code = 0;
    std::vector<uint8_t> data;
};

class Driver {
public:
    Driver(uart_port_t port, int tx_gpio, int rx_gpio, int baud_rate);

    void initialize();
    TransactionResult set_led(LedColor color, uint32_t timeout_ms = 300);
    TransactionResult get_image(uint32_t timeout_ms = 300);
    TransactionResult template_count(uint32_t timeout_ms = 300);
    TransactionResult read_index_page(uint8_t page, uint32_t timeout_ms = 300);
    TransactionResult image_to_template(uint8_t buffer_id, uint32_t timeout_ms = 300);
    TransactionResult search_template(uint8_t buffer_id, uint16_t start_slot, uint16_t slot_count,
                                      uint32_t timeout_ms = 750);
    TransactionResult create_model(uint32_t timeout_ms = 300);
    TransactionResult store_model(uint8_t buffer_id, uint16_t slot, uint32_t timeout_ms = 500);
    TransactionResult delete_model(uint16_t slot, uint32_t timeout_ms = 500);
    TransactionResult empty_database(uint32_t timeout_ms = 3000);

private:
    TransactionResult transact(uint8_t instruction, const std::vector<uint8_t>& parameters,
                               size_t expected_success_data_size, uint32_t timeout_ms);

    uart_port_t port_;
    int tx_gpio_;
    int rx_gpio_;
    int baud_rate_;
};

}
