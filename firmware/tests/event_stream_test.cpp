#include "audit_events.hpp"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

namespace {
using namespace fg;

void require(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}

AuditRecord event(uint16_t slot, const char* name = "")
{
    AuditRecord value;
    value.type = AuditType::Access;
    value.result = AuditResultCode::Granted;
    value.source = AuditSource::Fingerprint;
    value.slot = slot;
    std::snprintf(value.name.data(), value.name.size(), "%s", name);
    return value;
}

void append(AuditPublisher& publisher, AuditRecord value)
{
    require(publisher.publish(value), "test event enters the publisher queue");
    require(publisher.drain(1) == 1, "test event is persisted");
}

void test_single_subscriber_replays_then_delivers_live_in_order()
{
    MemoryAuditStorage storage;
    AuditStore store(storage);
    require(store.initialize() == AuditResult::Ok, "initialize audit store");
    AuditPublisher publisher(store);
    append(publisher, event(1));
    append(publisher, event(2));

    AuditEventStream stream(publisher, 2);
    AuditPage replay;
    require(stream.open({1, 1}, 7, &replay) == EventStreamResult::Ok, "first subscriber opens");
    require(replay.events.size() == 1 && replay.events[0].slot == 2, "retained event replays after cursor");

    AuditEventStream second(publisher, 2);
    require(second.open({}, 7, &replay) == EventStreamResult::Busy, "second subscriber is rejected");

    append(publisher, event(3));
    AuditRecord live;
    require(stream.take_next(7, &live) && live.slot == 3, "live event follows replay in sequence");
}

void test_expired_cursor_resets_and_queue_overflow_closes_stream()
{
    MemoryAuditStorage storage;
    AuditStore store(storage);
    require(store.initialize() == AuditResult::Ok, "initialize audit store");
    AuditPublisher publisher(store);
    for (uint16_t slot = 0; slot < 513; ++slot) append(publisher, event(slot));

    AuditEventStream stream(publisher, 1);
    AuditPage replay;
    require(stream.open({1, 1}, 9, &replay) == EventStreamResult::Reset, "expired cursor requires reset");
    require(stream.open({}, 9, &replay) == EventStreamResult::Ok, "reset stream opens from retained range");

    append(publisher, event(514));
    append(publisher, event(515));
    require(stream.closed(), "full outbound queue closes the subscriber");
}

void test_generation_change_closes_and_sse_json_is_escaped()
{
    MemoryAuditStorage storage;
    AuditStore store(storage);
    require(store.initialize() == AuditResult::Ok, "initialize audit store");
    AuditPublisher publisher(store);
    AuditEventStream stream(publisher, 2);
    AuditPage replay;
    require(stream.open({}, 10, &replay) == EventStreamResult::Ok, "stream opens");
    append(publisher, event(4, "quoted\"\\\nname"));

    AuditRecord live;
    require(!stream.take_next(11, &live) && stream.closed(), "token generation change closes the stream");

    const AuditRecord escaped = event(5, "quoted\"\\\nname");
    const std::string frame = AuditEventStream::sse_frame(escaped);
    require(frame.find("id: 0:0\n") == 0, "frame uses opaque event ID");
    require(frame.find("event: access.granted\n") != std::string::npos, "frame names event type and result");
    require(frame.find("quoted\\\"\\\\\\u000aname") != std::string::npos, "frame escapes JSON strings");
}

class ReentrantSubscriber final : public AuditSubscriber {
public:
    explicit ReentrantSubscriber(AuditPublisher& publisher) : publisher_(publisher) {}

    bool on_audit_record(const AuditRecord&) override
    {
        publisher_.unsubscribe(*this);
        called = true;
        return true;
    }

    bool called = false;

private:
    AuditPublisher& publisher_;
};

void test_subscriber_can_unsubscribe_from_delivery_callback()
{
    MemoryAuditStorage storage;
    AuditStore store(storage);
    require(store.initialize() == AuditResult::Ok, "initialize audit store");
    AuditPublisher publisher(store);
    ReentrantSubscriber subscriber(publisher);
    require(publisher.subscribe(subscriber), "subscriber registers");
    append(publisher, event(1));
    require(subscriber.called, "subscriber can synchronously unsubscribe from callback");
}

void test_sse_frame_handles_a_maximum_length_request_id()
{
    AuditRecord record = event(1);
    record.request_id.fill('a');
    const std::string frame = AuditEventStream::sse_frame(record);
    require(frame.find(std::string(64, 'a')) != std::string::npos, "maximum request ID is emitted without reading past its field");
}
}

int main()
{
    test_single_subscriber_replays_then_delivers_live_in_order();
    test_expired_cursor_resets_and_queue_overflow_closes_stream();
    test_generation_change_closes_and_sse_json_is_escaped();
    test_subscriber_can_unsubscribe_from_delivery_callback();
    test_sse_frame_handles_a_maximum_length_request_id();
    return EXIT_SUCCESS;
}
