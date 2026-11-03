#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace r558s {

constexpr uint8_t kPacketHeaderFirst = 0xEF;
constexpr uint8_t kPacketHeaderSecond = 0x01;
constexpr uint8_t kPacketTypeCommand = 0x01;
constexpr uint8_t kPacketTypeAck = 0x07;
constexpr uint8_t kInstructionGetImage = 0x01;
constexpr uint16_t kMinimumPacketLength = 3;
constexpr uint16_t kMaximumPacketLength = 256;

struct Packet {
    uint32_t address = 0;
    uint8_t type = 0;
    std::vector<uint8_t> payload;
};

enum class AckResult {
    Success,
    SensorRejected,
    InvalidPacket,
};

std::vector<uint8_t> make_command(uint8_t instruction, const std::vector<uint8_t>& parameters);
AckResult decode_ack(const Packet& packet, size_t expected_success_data_size, size_t allowed_rejection_data_size = 0);

class FrameParser {
public:
    std::optional<Packet> push(uint8_t byte);
    uint32_t invalid_frame_count() const;

private:
    std::vector<uint8_t> bytes_;
    uint32_t invalid_frame_count_ = 0;
};

}
