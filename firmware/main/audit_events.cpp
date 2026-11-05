#include "audit_events.hpp"

#include <algorithm>

namespace fg {
namespace {
std::string json_string(const std::string& value)
{
    std::string escaped{"\""};
    constexpr char kHex[] = "0123456789abcdef";
    for (const unsigned char character : value) {
        if (character == '\\') escaped += "\\\\";
        else if (character == '"') escaped += "\\\"";
        else if (character < 0x20) {
            escaped += "\\u00";
            escaped += kHex[character >> 4];
            escaped += kHex[character & 0x0f];
        } else escaped += static_cast<char>(character);
    }
    return escaped + '"';
}
}

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
        AuditPage committed;
        {
            std::lock_guard<std::mutex> lock(storage_mutex_);
            if (store_.append(record) != AuditResult::Ok ||
                store_.read_after({}, AuditStore::kRecordCapacity, &committed) != AuditResult::Ok || committed.events.empty()) {
                ++failed_count_;
                continue;
            }
        }
        if (committed.events.empty()) {
            ++failed_count_;
            continue;
        }
        record = committed.events.back();
        ++persisted;
        deliver(record);
    }
    return persisted;
}

bool AuditPublisher::append(AuditRecord record)
{
    AuditPage committed;
    {
        std::lock_guard<std::mutex> lock(storage_mutex_);
        if (store_.append(record) != AuditResult::Ok ||
            store_.read_after({}, AuditStore::kRecordCapacity, &committed) != AuditResult::Ok || committed.events.empty()) {
            ++failed_count_;
            return false;
        }
    }
    if (committed.events.empty()) {
        ++failed_count_;
        return false;
    }
    deliver(committed.events.back());
    return true;
}

void AuditPublisher::deliver(const AuditRecord& record)
{
    AuditSubscriber* subscriber = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        last_committed_ = record.id;
        if (subscriber_ && (record.id.epoch != subscriber_after_.epoch || record.id.sequence > subscriber_after_.sequence))
            subscriber = subscriber_;
    }
    if (!subscriber) return;
    const bool delivered = subscriber->on_audit_record(record);
    std::lock_guard<std::mutex> lock(mutex_);
    if (subscriber_ != subscriber) return;
    if (delivered) subscriber_after_ = record.id;
    else subscriber_ = nullptr;
}

bool AuditPublisher::subscribe(AuditSubscriber& subscriber)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (subscriber_) return false;
    subscriber_ = &subscriber;
    subscriber_after_ = {};
    return true;
}

EventStreamResult AuditPublisher::subscribe_after(AuditSubscriber& subscriber, AuditCursor after, AuditPage* replay)
{
    if (!replay) return EventStreamResult::Unavailable;
    for (;;) {
        // Flash reads stay outside the ordering mutex; retry when a committed event races registration.
        const AuditResult result = store_.read_after(after, AuditStore::kRecordCapacity, replay);
        if (result == AuditResult::Invalid) return EventStreamResult::Reset;
        if (result != AuditResult::Ok) return EventStreamResult::Unavailable;
        std::lock_guard<std::mutex> lock(mutex_);
        if (subscriber_) return EventStreamResult::Busy;
        if (last_committed_.epoch == replay->next_after.epoch && last_committed_.sequence > replay->next_after.sequence) {
            after = replay->next_after;
            continue;
        }
        subscriber_ = &subscriber;
        subscriber_after_ = replay->next_after;
        return EventStreamResult::Ok;
    }
}

void AuditPublisher::unsubscribe(AuditSubscriber& subscriber)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (subscriber_ == &subscriber) subscriber_ = nullptr;
}

AuditEventStream::AuditEventStream(AuditPublisher& publisher, size_t capacity)
    : publisher_(publisher), capacity_(capacity) {}

EventStreamResult AuditEventStream::open(AuditCursor after, uint32_t token_generation, AuditPage* replay)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (active_) return EventStreamResult::Busy;
        token_generation_ = token_generation;
        head_ = 0;
        queue_.clear();
        active_ = true;
        closed_ = false;
    }
    const EventStreamResult result = publisher_.subscribe_after(*this, after, replay);
    if (result != EventStreamResult::Ok) {
        std::lock_guard<std::mutex> lock(mutex_);
        active_ = false;
        closed_ = result != EventStreamResult::Busy;
    }
    return result;
}

void AuditEventStream::close()
{
    bool unsubscribe = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        unsubscribe = active_;
        active_ = false;
        closed_ = true;
        queue_.clear();
        head_ = 0;
    }
    if (unsubscribe) publisher_.unsubscribe(*this);
}

bool AuditEventStream::closed() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return closed_;
}

bool AuditEventStream::take_next(uint32_t token_generation, AuditRecord* record)
{
    bool unsubscribe = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_ || token_generation != token_generation_) {
            unsubscribe = active_;
            active_ = false;
            closed_ = true;
        } else if (!queue_.empty() && record) {
            *record = queue_.front();
            queue_.erase(queue_.begin());
            return true;
        }
    }
    if (unsubscribe) publisher_.unsubscribe(*this);
    return false;
}

bool AuditEventStream::on_audit_record(const AuditRecord& record)
{
    std::function<void()> ready;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_ || queue_.size() == capacity_) {
            active_ = false;
            closed_ = true;
            return false;
        }
        queue_.push_back(record);
        ready = ready_callback_;
    }
    if (ready) ready();
    return true;
}

void AuditEventStream::set_ready_callback(std::function<void()> callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    ready_callback_ = std::move(callback);
}

std::string AuditEventStream::sse_frame(const AuditRecord& record)
{
    const char* const types[] = {"access", "enrollment", "user", "authentication", "network", "gate", "system"};
    const char* const results[] = {"granted", "rejected", "accepted", "failed", "cleared"};
    const size_t type = static_cast<size_t>(record.type);
    const size_t result = static_cast<size_t>(record.result);
    const std::string id = std::to_string(record.id.epoch) + ":" + std::to_string(record.id.sequence);
    const std::string name(record.name.data(), std::find(record.name.begin(), record.name.end(), '\0'));
    const std::string request_id(record.request_id.data(), std::find(record.request_id.begin(), record.request_id.end(), '\0'));
    return "id: " + id + "\n" +
           "event: " + std::string(type < std::size(types) ? types[type] : "system") + "." +
           (result < std::size(results) ? results[result] : "failed") + "\n" +
           "data: {\"id\":" + json_string(id) + ",\"type\":" + json_string(type < std::size(types) ? types[type] : "system") +
           ",\"result\":" + json_string(result < std::size(results) ? results[result] : "failed") +
           ",\"source\":" + std::to_string(static_cast<unsigned>(record.source)) + ",\"slot\":" +
           std::to_string(record.slot) + ",\"name\":" + json_string(name) + ",\"request_id\":" +
           json_string(request_id) + "}\n\n";
}

}
