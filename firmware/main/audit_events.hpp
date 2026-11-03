#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>

namespace fg {

enum class AuditEventType : uint8_t { Recognition, Rejection, Enrollment, Deletion, GatePulse };

struct AuditEvent {
    AuditEventType type;
    uint16_t slot;
};

class AuditEventSink {
public:
    explicit AuditEventSink(size_t capacity) : capacity_(capacity) {}
    bool publish(AuditEvent event);
    uint32_t dropped_count() const { return dropped_count_; }

private:
    size_t capacity_;
    uint32_t dropped_count_ = 0;
    std::deque<AuditEvent> events_;
};

}
