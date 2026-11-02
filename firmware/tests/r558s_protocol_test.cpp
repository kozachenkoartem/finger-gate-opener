#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <vector>

#include "r558s_protocol.hpp"

namespace {

void require(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}

std::vector<uint8_t> bytes(std::initializer_list<uint8_t> values)
{
    return {values};
}

void test_get_image_command()
{
    const auto command = r558s::make_command(r558s::kInstructionGetImage, {});
    require(command == bytes({0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF,
                              0x01, 0x00, 0x03, 0x01, 0x00, 0x05}),
            "GetImage packet must match the R558S protocol");
}

void test_fragmented_ack()
{
    r558s::FrameParser parser;
    const auto frame = bytes({0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF,
                              0x07, 0x00, 0x03, 0x00, 0x00, 0x0A});

    for (size_t index = 0; index + 1 < frame.size(); ++index) {
        require(!parser.push(frame[index]).has_value(), "partial ACK must not complete a frame");
    }

    const auto packet = parser.push(frame.back());
    require(packet.has_value(), "complete ACK must produce a frame");
    require(packet->type == r558s::kPacketTypeAck, "ACK packet type must be retained");
    require(packet->payload == bytes({0x00}), "ACK payload must retain confirmation code");
}

void test_parser_resynchronizes_after_garbage()
{
    r558s::FrameParser parser;
    const auto frame = bytes({0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF,
                              0x07, 0x00, 0x03, 0x02, 0x00, 0x0C});

    for (const uint8_t byte : bytes({0x11, 0xEF, 0x00, 0xAA})) {
        require(!parser.push(byte).has_value(), "garbage must not produce a frame");
    }

    std::optional<r558s::Packet> packet;
    for (const uint8_t byte : frame) {
        packet = parser.push(byte);
    }
    require(packet.has_value(), "parser must recover after garbage");
    require(packet->payload == bytes({0x02}), "recovered packet payload must be intact");
}

void test_parser_rejects_invalid_checksum()
{
    r558s::FrameParser parser;
    const auto frame = bytes({0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF,
                              0x07, 0x00, 0x03, 0x00, 0x00, 0x0B});

    for (const uint8_t byte : frame) {
        require(!parser.push(byte).has_value(), "invalid checksum must not produce a frame");
    }
    require(parser.invalid_frame_count() == 1, "invalid checksum must be counted");
}

void test_parser_rejects_invalid_length()
{
    r558s::FrameParser parser;
    const auto frame = bytes({0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF,
                              0x07, 0x00, 0x02, 0x00, 0x09});

    for (const uint8_t byte : frame) {
        require(!parser.push(byte).has_value(), "invalid length must not produce a frame");
    }
    require(parser.invalid_frame_count() == 1, "invalid length must be counted");
}

void test_ack_result_distinguishes_sensor_rejection()
{
    r558s::Packet accepted;
    accepted.address = 0xFFFFFFFF;
    accepted.type = r558s::kPacketTypeAck;
    accepted.payload = {0x00};

    r558s::Packet rejected = accepted;
    rejected.payload = {0x09};

    r558s::Packet search_result = accepted;
    search_result.payload = {0x00, 0x00, 0x03, 0x00, 0x80};

    require(r558s::decode_ack(accepted, 0) == r558s::AckResult::Success,
            "zero confirmation code must be successful");
    require(r558s::decode_ack(rejected, 4) == r558s::AckResult::SensorRejected,
            "non-zero confirmation code must be a sensor rejection");
    require(r558s::decode_ack(search_result, 4) == r558s::AckResult::Success,
            "search response must accept its expected ID and score payload");
    require(r558s::decode_ack(search_result, 0) == r558s::AckResult::InvalidPacket,
            "successful response with unexpected payload must be rejected");
}

}

int main()
{
    test_get_image_command();
    test_fragmented_ack();
    test_parser_resynchronizes_after_garbage();
    test_parser_rejects_invalid_checksum();
    test_parser_rejects_invalid_length();
    test_ack_result_distinguishes_sensor_rejection();
    return EXIT_SUCCESS;
}
