#pragma once

#include <atomic>
#include <cstddef>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include "audit_store.hpp"

namespace fg {

class AuditSubscriber {
public:
    virtual ~AuditSubscriber() = default;
    virtual bool on_audit_record(const AuditRecord& record) = 0;
};

enum class EventStreamResult { Ok, Busy, Reset, Unavailable };

class AuditPublisher {
public:
    explicit AuditPublisher(AuditStore& store, size_t capacity = 16);

    bool publish(AuditRecord record);
    bool append(AuditRecord record);
    size_t drain(size_t maximum);
    bool subscribe(AuditSubscriber& subscriber);
    EventStreamResult subscribe_after(AuditSubscriber& subscriber, AuditCursor after, AuditPage* replay);
    void unsubscribe(AuditSubscriber& subscriber);
    uint32_t dropped_count() const { return dropped_count_.load(); }
    uint32_t failed_count() const { return failed_count_.load(); }
    AuditStore& store() { return store_; }

private:
    AuditStore& store_;
    std::vector<AuditRecord> queue_;
    size_t head_ = 0;
    size_t size_ = 0;
    std::mutex mutex_;
    std::mutex storage_mutex_;
    AuditSubscriber* subscriber_ = nullptr;
    AuditCursor subscriber_after_{};
    AuditCursor last_committed_{};
    std::atomic<uint32_t> dropped_count_{0};
    std::atomic<uint32_t> failed_count_{0};
    void deliver(const AuditRecord& record);
};

class AuditEventStream final : public AuditSubscriber {
public:
    explicit AuditEventStream(AuditPublisher& publisher, size_t capacity = 8);
    ~AuditEventStream() override { close(); }

    EventStreamResult open(AuditCursor after, uint32_t token_generation, AuditPage* replay);
    void close();
    bool closed() const;
    bool take_next(uint32_t token_generation, AuditRecord* record);
    bool on_audit_record(const AuditRecord& record) override;
    void set_ready_callback(std::function<void()> callback);
    static std::string sse_frame(const AuditRecord& record);

private:
    AuditPublisher& publisher_;
    const size_t capacity_;
    mutable std::mutex mutex_;
    std::vector<AuditRecord> queue_;
    size_t head_ = 0;
    uint32_t token_generation_ = 0;
    bool active_ = false;
    bool closed_ = false;
    std::function<void()> ready_callback_;
};

}
