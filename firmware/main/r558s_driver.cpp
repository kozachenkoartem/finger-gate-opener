#include "r558s_driver.hpp"

#include "driver/uart.h"
#include "esp_err.h"
#include "esp_timer.h"

#include "r558s_protocol.hpp"

namespace r558s {
namespace {

constexpr int kRxBufferSize = 256;
constexpr uint32_t kMicrosecondsPerMillisecond = 1000;
constexpr uint32_t kDefaultAddress = 0xFFFFFFFF;
constexpr uint8_t kInstructionImageToTemplate = 0x02;
constexpr uint8_t kInstructionCreateModel = 0x05;
constexpr uint8_t kInstructionStoreModel = 0x06;
constexpr uint8_t kInstructionSearch = 0x04;
constexpr uint8_t kInstructionDeleteModel = 0x0C;
constexpr uint8_t kInstructionSetLed = 0x3C;

std::vector<uint8_t> uint16_parameters(uint16_t value)
{
    return {static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value)};
}

}

Driver::Driver(uart_port_t port, int tx_gpio, int rx_gpio, int baud_rate)
    : port_(port), tx_gpio_(tx_gpio), rx_gpio_(rx_gpio), baud_rate_(baud_rate)
{
}

void Driver::initialize()
{
    const uart_config_t configuration = {
        .baud_rate = baud_rate_,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .rx_flow_ctrl_thresh = 0,
        .source_clk = UART_SCLK_DEFAULT,
        .flags = {},
    };

    ESP_ERROR_CHECK(uart_param_config(port_, &configuration));
    ESP_ERROR_CHECK(uart_set_pin(port_, tx_gpio_, rx_gpio_, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    ESP_ERROR_CHECK(uart_driver_install(port_, kRxBufferSize, 0, 0, nullptr, 0));
}

TransactionResult Driver::set_led(LedColor color, uint32_t timeout_ms)
{
    const auto mode = static_cast<uint8_t>(color);
    return transact(kInstructionSetLed, {0x03, mode, mode, 0x00, 0x00}, 0, timeout_ms);
}

TransactionResult Driver::get_image(uint32_t timeout_ms)
{
    return transact(kInstructionGetImage, {}, 0, timeout_ms);
}

TransactionResult Driver::image_to_template(uint8_t buffer_id, uint32_t timeout_ms)
{
    return transact(kInstructionImageToTemplate, {buffer_id}, 0, timeout_ms);
}

TransactionResult Driver::search_template(uint8_t buffer_id, uint16_t start_slot, uint16_t slot_count,
                                           uint32_t timeout_ms)
{
    auto parameters = std::vector<uint8_t>{buffer_id};
    const auto start = uint16_parameters(start_slot);
    const auto count = uint16_parameters(slot_count);
    parameters.insert(parameters.end(), start.begin(), start.end());
    parameters.insert(parameters.end(), count.begin(), count.end());
    return transact(kInstructionSearch, parameters, 4, timeout_ms);
}

TransactionResult Driver::create_model(uint32_t timeout_ms)
{
    return transact(kInstructionCreateModel, {}, 0, timeout_ms);
}

TransactionResult Driver::store_model(uint8_t buffer_id, uint16_t slot, uint32_t timeout_ms)
{
    const auto slot_bytes = uint16_parameters(slot);
    return transact(kInstructionStoreModel, {buffer_id, slot_bytes[0], slot_bytes[1]}, 0, timeout_ms);
}

TransactionResult Driver::delete_model(uint16_t slot, uint32_t timeout_ms)
{
    const auto slot_bytes = uint16_parameters(slot);
    return transact(kInstructionDeleteModel, {slot_bytes[0], slot_bytes[1], 0x00, 0x01}, 0, timeout_ms);
}

TransactionResult Driver::transact(uint8_t instruction, const std::vector<uint8_t>& parameters,
                                   size_t expected_success_data_size, uint32_t timeout_ms)
{
    TransactionResult result;
    const int64_t deadline = esp_timer_get_time() + static_cast<int64_t>(timeout_ms) * kMicrosecondsPerMillisecond;
    const auto command = make_command(instruction, parameters);
    ESP_ERROR_CHECK(uart_flush_input(port_));

    const int written = uart_write_bytes(port_, command.data(), command.size());
    if (written != static_cast<int>(command.size())) {
        result.status = TransactionStatus::WriteFailure;
        return result;
    }

    const int64_t transmit_remaining_us = deadline - esp_timer_get_time();
    if (transmit_remaining_us <= 0 ||
        uart_wait_tx_done(port_, pdMS_TO_TICKS(transmit_remaining_us / kMicrosecondsPerMillisecond)) != ESP_OK) {
        result.status = TransactionStatus::Timeout;
        return result;
    }

    FrameParser parser;
    while (esp_timer_get_time() < deadline) {
        const int64_t remaining_us = deadline - esp_timer_get_time();
        const TickType_t remaining_ticks = pdMS_TO_TICKS(remaining_us / kMicrosecondsPerMillisecond);
        uint8_t byte = 0;
        const int received = uart_read_bytes(port_, &byte, 1, remaining_ticks);
        if (received <= 0) {
            break;
        }

        const auto packet = parser.push(byte);
        if (!packet.has_value()) {
            continue;
        }
        if (packet->address != kDefaultAddress || packet->type != kPacketTypeAck) {
            result.status = TransactionStatus::InvalidResponse;
            return result;
        }

        const AckResult acknowledgement = decode_ack(*packet, expected_success_data_size);
        if (acknowledgement == AckResult::InvalidPacket) {
            result.status = TransactionStatus::InvalidResponse;
            return result;
        }

        result.confirmation_code = packet->payload.front();
        result.data.assign(packet->payload.begin() + 1, packet->payload.end());
        result.status = acknowledgement == AckResult::Success ? TransactionStatus::Success
                                                                : TransactionStatus::SensorRejected;
        return result;
    }

    result.status = TransactionStatus::Timeout;
    return result;
}

}
