#include "r558s_protocol.hpp"

namespace r558s {
namespace {

constexpr size_t kHeaderSize = 9;
constexpr size_t kChecksumSize = 2;

uint16_t checksum(const std::vector<uint8_t>& bytes, size_t first, size_t last)
{
    uint16_t value = 0;
    for (size_t index = first; index < last; ++index) {
        value += bytes[index];
    }
    return value;
}

}

std::vector<uint8_t> make_command(uint8_t instruction, const std::vector<uint8_t>& parameters)
{
    const uint16_t length = parameters.size() + 3;
    std::vector<uint8_t> command = {
        kPacketHeaderFirst, kPacketHeaderSecond,
        0xFF, 0xFF, 0xFF, 0xFF,
        kPacketTypeCommand,
        static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length),
        instruction,
    };
    command.insert(command.end(), parameters.begin(), parameters.end());

    const uint16_t value = checksum(command, 6, command.size());
    command.push_back(static_cast<uint8_t>(value >> 8));
    command.push_back(static_cast<uint8_t>(value));
    return command;
}

AckResult decode_ack(const Packet& packet, size_t expected_success_data_size, size_t allowed_rejection_data_size)
{
    if (packet.type != kPacketTypeAck || packet.payload.empty()) {
        return AckResult::InvalidPacket;
    }
    if (packet.payload.front() != 0) {
        return packet.payload.size() == 1 || packet.payload.size() == allowed_rejection_data_size + 1
            ? AckResult::SensorRejected : AckResult::InvalidPacket;
    }
    return packet.payload.size() == expected_success_data_size + 1 ? AckResult::Success
                                                                     : AckResult::InvalidPacket;
}

std::optional<Packet> FrameParser::push(uint8_t byte)
{
    bytes_.push_back(byte);

    while (true) {
        auto header = bytes_.end();
        for (auto candidate = bytes_.begin(); candidate != bytes_.end(); ++candidate) {
            if (*candidate == kPacketHeaderFirst && candidate + 1 != bytes_.end() &&
                *(candidate + 1) == kPacketHeaderSecond) {
                header = candidate;
                break;
            }
        }
        if (header == bytes_.end()) {
            const bool keep_first_header_byte = !bytes_.empty() && bytes_.back() == kPacketHeaderFirst;
            bytes_.clear();
            if (keep_first_header_byte) {
                bytes_.push_back(kPacketHeaderFirst);
            }
            return std::nullopt;
        }
        if (header != bytes_.begin()) {
            bytes_.erase(bytes_.begin(), header);
        }
        if (bytes_.size() < kHeaderSize) {
            return std::nullopt;
        }

        const uint16_t length = (static_cast<uint16_t>(bytes_[7]) << 8) | bytes_[8];
        if (length < kMinimumPacketLength || length > kMaximumPacketLength) {
            ++invalid_frame_count_;
            bytes_.erase(bytes_.begin());
            continue;
        }

        const size_t frame_size = kHeaderSize + length;
        if (bytes_.size() < frame_size) {
            return std::nullopt;
        }

        const uint16_t expected = (static_cast<uint16_t>(bytes_[frame_size - 2]) << 8) |
                                  bytes_[frame_size - 1];
        if (checksum(bytes_, 6, frame_size - kChecksumSize) != expected) {
            ++invalid_frame_count_;
            bytes_.erase(bytes_.begin());
            continue;
        }

        Packet packet;
        packet.address = (static_cast<uint32_t>(bytes_[2]) << 24) |
                         (static_cast<uint32_t>(bytes_[3]) << 16) |
                         (static_cast<uint32_t>(bytes_[4]) << 8) |
                         bytes_[5];
        packet.type = bytes_[6];
        packet.payload.assign(bytes_.begin() + kHeaderSize, bytes_.begin() + frame_size - kChecksumSize);
        bytes_.erase(bytes_.begin(), bytes_.begin() + frame_size);
        return packet;
    }
}

uint32_t FrameParser::invalid_frame_count() const
{
    return invalid_frame_count_;
}

}
