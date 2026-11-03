#include "audit_events.hpp"

namespace fg {

bool AuditEventSink::publish(AuditEvent event)
{
    if (events_.size() == capacity_) {
        ++dropped_count_;
        return false;
    }
    events_.push_back(event);
    return true;
}

}
