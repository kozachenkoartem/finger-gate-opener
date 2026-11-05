#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#ifdef ESP_PLATFORM
#include "esp_partition.h"
#endif

namespace fg {

enum class AuditResult { Ok, Invalid, Corrupt, Unavailable };
enum class AuditType : uint8_t { Access, Enrollment, User, Authentication, Network, Gate, System };
enum class AuditResultCode : uint8_t { Granted, Rejected, Accepted, Failed, Cleared };
enum class AuditSource : uint8_t { Fingerprint, Admin, Hub, Device };

struct AuditCursor {
    uint32_t epoch = 0;
    uint64_t sequence = 0;
};

struct AuditRecord {
    AuditType type = AuditType::Access;
    AuditResultCode result = AuditResultCode::Granted;
    AuditSource source = AuditSource::Fingerprint;
    uint16_t slot = 0;
    uint64_t elapsed_ms = 0;
    AuditCursor id;
    std::array<char, 64> name{};
    std::array<char, 64> request_id{};
};

struct AuditPage {
    std::vector<AuditRecord> events;
    AuditCursor next_after;
    bool has_more = false;
};

class AuditStorage {
public:
    virtual ~AuditStorage() = default;
    virtual size_t size() const = 0;
    virtual AuditResult read(size_t offset, void* data, size_t size) const = 0;
    virtual AuditResult write(size_t offset, const void* data, size_t size) = 0;
    virtual AuditResult erase(size_t offset, size_t size) = 0;
};

class MemoryAuditStorage final : public AuditStorage {
public:
    MemoryAuditStorage();

    size_t size() const override;
    AuditResult read(size_t offset, void* data, size_t size) const override;
    AuditResult write(size_t offset, const void* data, size_t size) override;
    AuditResult erase(size_t offset, size_t size) override;

    void fail_after_write_bytes(size_t bytes);
    void fail_next_append() { fail_after_write_bytes(0); }
    void fail_next_commit() { fail_after_write_bytes(0); }
    void fail_after_erase_operations(size_t operations);
    void fail_next_erase() { fail_after_erase_operations(0); }
    void corrupt_byte(size_t offset);

private:
    std::vector<uint8_t> bytes_;
    size_t write_bytes_before_failure_ = kNoFailure;
    size_t erase_operations_before_failure_ = kNoFailure;
    static constexpr size_t kNoFailure = static_cast<size_t>(-1);
};

class AuditStore {
public:
    static constexpr size_t kSectorSize = 4096;
    static constexpr size_t kRecordSize = 512;
    static constexpr size_t kRecordSectors = 64;
    static constexpr size_t kRecordCapacity = 512;
    static constexpr size_t kDataOffset = 2 * kSectorSize;
    static constexpr size_t kPartitionSize = 67 * kSectorSize;

    explicit AuditStore(AuditStorage& storage) : storage_(storage) {}

    AuditResult initialize();
    AuditResult append(AuditRecord event);
    AuditResult read_after(AuditCursor after, size_t limit, AuditPage* page);
    AuditResult clear();

private:
    struct Metadata;
    struct StoredRecord;

    AuditResult load_records(std::vector<StoredRecord>* records) const;
    AuditResult write_metadata(bool clearing, uint32_t epoch, uint64_t reserved_next);
    AuditResult complete_clear();
    AuditResult write_record(size_t offset, const AuditRecord& record);
    bool initialized_ = false;
    bool clearing_ = false;
    uint32_t epoch_ = 0;
    uint64_t next_sequence_ = 0;
    uint64_t reserved_next_ = 0;
    uint64_t metadata_generation_ = 0;
    int metadata_slot_ = -1;
    AuditStorage& storage_;
};

#ifdef ESP_PLATFORM
class EspAuditStorage final : public AuditStorage {
public:
    EspAuditStorage();

    size_t size() const override;
    AuditResult read(size_t offset, void* data, size_t size) const override;
    AuditResult write(size_t offset, const void* data, size_t size) override;
    AuditResult erase(size_t offset, size_t size) override;

private:
    const ::esp_partition_t* partition_ = nullptr;
};
#endif

}
