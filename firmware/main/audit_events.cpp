#include "audit_events.hpp"

namespace fg {

AuditPublisher::AuditPublisher(AuditStore& store, size_t capacity) : store_(store), queue_(capacity) {}

bool AuditPublisher::publish(AuditRecord record)
{
    std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);
    if (!lock.owns_lock() || queue_.empty() || size_ == queue_.size()) {
        ++dropped_count_;
        return false;
    }
    queue_[(head_ + size_) % queue_.size()] = record;
    ++size_;
    return true;
}

size_t AuditPublisher::drain(size_t maximum)
{
    size_t persisted = 0;
    while (persisted < maximum) {
        AuditRecord record;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!size_) break;
            record = queue_[head_];
            head_ = (head_ + 1) % queue_.size();
            --size_;
        }
        if (store_.append(record) != AuditResult::Ok) {
            ++failed_count_;
            continue;
        }
        ++persisted;
        AuditSubscriber* subscriber = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            subscriber = subscriber_;
        }
        if (subscriber) subscriber->on_audit_record(record);
    }
    return persisted;
}

bool AuditPublisher::subscribe(AuditSubscriber& subscriber)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (subscriber_) return false;
    subscriber_ = &subscriber;
    return true;
}

void AuditPublisher::unsubscribe(AuditSubscriber& subscriber)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (subscriber_ == &subscriber) subscriber_ = nullptr;
}

}
