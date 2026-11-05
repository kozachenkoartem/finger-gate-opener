#pragma once

#include <atomic>
#include <cstddef>
#include <mutex>
#include <vector>

#include "audit_store.hpp"

namespace fg {

class AuditSubscriber {
public:
    virtual ~AuditSubscriber() = default;
    virtual void on_audit_record(const AuditRecord& record) = 0;
};

class AuditPublisher {
public:
    explicit AuditPublisher(AuditStore& store, size_t capacity = 16);

    bool publish(AuditRecord record);
    size_t drain(size_t maximum);
    bool subscribe(AuditSubscriber& subscriber);
    void unsubscribe(AuditSubscriber& subscriber);
    uint32_t dropped_count() const { return dropped_count_.load(); }
    uint32_t failed_count() const { return failed_count_.load(); }

private:
    AuditStore& store_;
    std::vector<AuditRecord> queue_;
    size_t head_ = 0;
    size_t size_ = 0;
    std::mutex mutex_;
    AuditSubscriber* subscriber_ = nullptr;
    std::atomic<uint32_t> dropped_count_{0};
    std::atomic<uint32_t> failed_count_{0};
};

}
