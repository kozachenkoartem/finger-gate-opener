#include "audit_store.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>

#ifdef ESP_PLATFORM
#include "esp_partition.h"
#endif

namespace fg {
namespace {
constexpr uint32_t kMetadataMagic = 0x4647414d;
constexpr uint32_t kRecordMagic = 0x46474152;
constexpr uint16_t kFormatVersion = 1;
constexpr size_t kMetadataCrcOffset = 32;
constexpr size_t kRecordCrcOffset = AuditStore::kRecordSize - sizeof(uint32_t);
constexpr uint64_t kSequenceReservation = 64;
std::mutex g_lock;

uint32_t crc32(const uint8_t* data, size_t size)
{
    uint32_t crc = 0xffffffffU;
    for (size_t index = 0; index < size; ++index) {
        crc ^= data[index];
        for (unsigned bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1U) ^ (0xedb88320U & static_cast<uint32_t>(-(crc & 1U)));
        }
    }
    return ~crc;
}

template <typename T>
void put(uint8_t* bytes, size_t offset, T value)
{
    for (size_t index = 0; index < sizeof(T); ++index) bytes[offset + index] = static_cast<uint8_t>(value >> (index * 8U));
}

template <typename T>
T get(const uint8_t* bytes, size_t offset)
{
    T value = 0;
    for (size_t index = 0; index < sizeof(T); ++index) value |= static_cast<T>(bytes[offset + index]) << (index * 8U);
    return value;
}

bool erased(const uint8_t* bytes, size_t size)
{
    return std::all_of(bytes, bytes + size, [](uint8_t value) { return value == 0xff; });
}
}

struct AuditStore::Metadata {
    bool clearing = false;
    uint64_t generation = 0;
    uint32_t epoch = 0;
    uint64_t reserved_next = 0;
};

struct AuditStore::StoredRecord {
    AuditRecord record;
    size_t offset = 0;
};

MemoryAuditStorage::MemoryAuditStorage() : bytes_(AuditStore::kPartitionSize, 0xff) {}

size_t MemoryAuditStorage::size() const { return bytes_.size(); }

AuditResult MemoryAuditStorage::read(size_t offset, void* data, size_t size) const
{
    if (offset > bytes_.size() || size > bytes_.size() - offset) return AuditResult::Invalid;
    std::memcpy(data, bytes_.data() + offset, size);
    return AuditResult::Ok;
}

AuditResult MemoryAuditStorage::write(size_t offset, const void* data, size_t size)
{
    if (offset > bytes_.size() || size > bytes_.size() - offset) return AuditResult::Invalid;
    const auto* source = static_cast<const uint8_t*>(data);
    const size_t writable = std::min(size, write_bytes_before_failure_);
    for (size_t index = 0; index < writable; ++index) {
        if ((bytes_[offset + index] & source[index]) != source[index]) return AuditResult::Unavailable;
        bytes_[offset + index] &= source[index];
    }
    if (write_bytes_before_failure_ != kNoFailure) {
        write_bytes_before_failure_ -= writable;
        if (writable != size) {
            write_bytes_before_failure_ = kNoFailure;
            return AuditResult::Unavailable;
        }
    }
    return AuditResult::Ok;
}

AuditResult MemoryAuditStorage::erase(size_t offset, size_t size)
{
    if (offset > bytes_.size() || size > bytes_.size() - offset || offset % AuditStore::kSectorSize != 0 ||
        size % AuditStore::kSectorSize != 0) return AuditResult::Invalid;
    if (erase_operations_before_failure_ != kNoFailure) {
        if (erase_operations_before_failure_ == 0) {
            erase_operations_before_failure_ = kNoFailure;
            return AuditResult::Unavailable;
        }
        --erase_operations_before_failure_;
    }
    std::fill(bytes_.begin() + offset, bytes_.begin() + offset + size, 0xff);
    return AuditResult::Ok;
}

void MemoryAuditStorage::fail_after_write_bytes(size_t bytes) { write_bytes_before_failure_ = bytes; }
void MemoryAuditStorage::fail_after_erase_operations(size_t operations) { erase_operations_before_failure_ = operations; }
void MemoryAuditStorage::corrupt_byte(size_t offset)
{
    if (offset < bytes_.size()) bytes_[offset] ^= 0x01;
}

AuditResult AuditStore::initialize()
{
    std::lock_guard<std::mutex> guard(g_lock);
    if (storage_.size() != kPartitionSize) return AuditResult::Invalid;

    std::array<uint8_t, kSectorSize> sector{};
    Metadata newest{};
    int newest_slot = -1;
    bool empty_metadata = true;
    for (int slot = 0; slot < 2; ++slot) {
        if (storage_.read(slot * kSectorSize, sector.data(), sector.size()) != AuditResult::Ok) return AuditResult::Unavailable;
        empty_metadata = empty_metadata && erased(sector.data(), sector.size());
        if (get<uint32_t>(sector.data(), 0) != kMetadataMagic || get<uint16_t>(sector.data(), 4) != kFormatVersion ||
            get<uint32_t>(sector.data(), kMetadataCrcOffset) != crc32(sector.data(), kMetadataCrcOffset)) continue;
        Metadata candidate{sector[6] != 0, get<uint64_t>(sector.data(), 8), get<uint32_t>(sector.data(), 16),
                           get<uint64_t>(sector.data(), 20)};
        if (candidate.epoch == 0 || candidate.reserved_next == 0) continue;
        if (newest_slot < 0 || candidate.generation > newest.generation) {
            newest = candidate;
            newest_slot = slot;
        }
    }
    if (newest_slot < 0) {
        if (!empty_metadata) return AuditResult::Corrupt;
        for (size_t offset = 0; offset < kPartitionSize; offset += kSectorSize) {
            const AuditResult result = storage_.erase(offset, kSectorSize);
            if (result != AuditResult::Ok) return result;
        }
        epoch_ = 1;
        reserved_next_ = 1;
        next_sequence_ = 1;
        metadata_generation_ = 0;
        metadata_slot_ = 1;
        clearing_ = false;
        const AuditResult result = write_metadata(false, epoch_, kSequenceReservation + 1);
        if (result != AuditResult::Ok) return result;
    } else {
        epoch_ = newest.epoch;
        reserved_next_ = newest.reserved_next;
        next_sequence_ = reserved_next_;
        metadata_generation_ = newest.generation;
        metadata_slot_ = newest_slot;
        clearing_ = newest.clearing;
        if (clearing_) {
            const AuditResult result = complete_clear();
            if (result != AuditResult::Ok) return result;
        }
    }
    initialized_ = true;
    return AuditResult::Ok;
}

AuditResult AuditStore::write_metadata(bool clearing, uint32_t epoch, uint64_t reserved_next)
{
    const int target_slot = metadata_slot_ == 0 ? 1 : 0;
    std::array<uint8_t, kSectorSize> bytes{};
    bytes.fill(0xff);
    put<uint32_t>(bytes.data(), 0, kMetadataMagic);
    put<uint16_t>(bytes.data(), 4, kFormatVersion);
    bytes[6] = clearing ? 1 : 0;
    put<uint64_t>(bytes.data(), 8, metadata_generation_ + 1);
    put<uint32_t>(bytes.data(), 16, epoch);
    put<uint64_t>(bytes.data(), 20, reserved_next);
    put<uint32_t>(bytes.data(), kMetadataCrcOffset, crc32(bytes.data(), kMetadataCrcOffset));
    AuditResult result = storage_.erase(target_slot * kSectorSize, kSectorSize);
    if (result != AuditResult::Ok) return result;
    result = storage_.write(target_slot * kSectorSize, bytes.data(), bytes.size());
    if (result != AuditResult::Ok) return result;
    std::array<uint8_t, kSectorSize> verify{};
    result = storage_.read(target_slot * kSectorSize, verify.data(), verify.size());
    if (result != AuditResult::Ok || std::memcmp(bytes.data(), verify.data(), bytes.size()) != 0) return AuditResult::Unavailable;
    ++metadata_generation_;
    metadata_slot_ = target_slot;
    clearing_ = clearing;
    epoch_ = epoch;
    reserved_next_ = reserved_next;
    return AuditResult::Ok;
}

AuditResult AuditStore::load_records(std::vector<StoredRecord>* records) const
{
    records->clear();
    std::array<uint8_t, kRecordSize> bytes{};
    const size_t slots = (kRecordSectors + 1) * (kSectorSize / kRecordSize);
    for (size_t slot = 0; slot < slots; ++slot) {
        const size_t offset = kDataOffset + slot * kRecordSize;
        const AuditResult result = storage_.read(offset, bytes.data(), bytes.size());
        if (result != AuditResult::Ok) return result;
        if (erased(bytes.data(), bytes.size()) || get<uint32_t>(bytes.data(), 0) != kRecordMagic ||
            get<uint16_t>(bytes.data(), 4) != kFormatVersion ||
            get<uint32_t>(bytes.data(), kRecordCrcOffset) != crc32(bytes.data(), kRecordCrcOffset)) continue;
        AuditRecord record{};
        record.type = static_cast<AuditType>(bytes[6]);
        record.result = static_cast<AuditResultCode>(bytes[7]);
        record.source = static_cast<AuditSource>(bytes[8]);
        record.slot = get<uint16_t>(bytes.data(), 10);
        record.id.epoch = get<uint32_t>(bytes.data(), 12);
        record.id.sequence = get<uint64_t>(bytes.data(), 16);
        record.elapsed_ms = get<uint64_t>(bytes.data(), 24);
        std::memcpy(record.name.data(), bytes.data() + 32, record.name.size());
        std::memcpy(record.request_id.data(), bytes.data() + 96, record.request_id.size());
        if (record.id.epoch == epoch_ && record.id.sequence != 0) records->push_back({record, offset});
    }
    std::sort(records->begin(), records->end(), [](const StoredRecord& left, const StoredRecord& right) {
        return left.record.id.sequence < right.record.id.sequence;
    });
    records->erase(std::unique(records->begin(), records->end(), [](const StoredRecord& left, const StoredRecord& right) {
        return left.record.id.sequence == right.record.id.sequence;
    }), records->end());
    if (records->size() > kRecordCapacity) records->erase(records->begin(), records->end() - kRecordCapacity);
    return AuditResult::Ok;
}

AuditResult AuditStore::write_record(size_t offset, const AuditRecord& record)
{
    std::array<uint8_t, kRecordSize> bytes{};
    bytes.fill(0xff);
    put<uint32_t>(bytes.data(), 0, kRecordMagic);
    put<uint16_t>(bytes.data(), 4, kFormatVersion);
    bytes[6] = static_cast<uint8_t>(record.type);
    bytes[7] = static_cast<uint8_t>(record.result);
    bytes[8] = static_cast<uint8_t>(record.source);
    put<uint16_t>(bytes.data(), 10, record.slot);
    put<uint32_t>(bytes.data(), 12, record.id.epoch);
    put<uint64_t>(bytes.data(), 16, record.id.sequence);
    put<uint64_t>(bytes.data(), 24, record.elapsed_ms);
    std::memcpy(bytes.data() + 32, record.name.data(), record.name.size());
    std::memcpy(bytes.data() + 96, record.request_id.data(), record.request_id.size());
    put<uint32_t>(bytes.data(), kRecordCrcOffset, crc32(bytes.data(), kRecordCrcOffset));
    return storage_.write(offset, bytes.data(), bytes.size());
}

AuditResult AuditStore::append(AuditRecord event)
{
    std::lock_guard<std::mutex> guard(g_lock);
    if (!initialized_ || clearing_) return AuditResult::Unavailable;
    if (next_sequence_ >= reserved_next_) {
        const AuditResult result = write_metadata(false, epoch_, next_sequence_ + kSequenceReservation);
        if (result != AuditResult::Ok) return result;
    }
    event.id = {epoch_, next_sequence_++};
    std::vector<StoredRecord> records;
    AuditResult result = load_records(&records);
    if (result != AuditResult::Ok) return result;
    if (records.size() < kRecordCapacity) {
        std::array<uint8_t, kRecordSize> bytes{};
        const size_t slots = (kRecordSectors + 1) * (kSectorSize / kRecordSize);
        for (size_t slot = 0; slot < slots; ++slot) {
            const size_t offset = kDataOffset + slot * kRecordSize;
            result = storage_.read(offset, bytes.data(), bytes.size());
            if (result != AuditResult::Ok) return result;
            if (erased(bytes.data(), bytes.size())) return write_record(offset, event);
        }
        return AuditResult::Unavailable;
    }
    const size_t oldest_sector = (records.front().offset - kDataOffset) / kSectorSize;
    size_t spare_sector = kRecordSectors + 1;
    std::array<uint8_t, kSectorSize> sector{};
    for (size_t index = 0; index <= kRecordSectors; ++index) {
        result = storage_.read(kDataOffset + index * kSectorSize, sector.data(), sector.size());
        if (result != AuditResult::Ok) return result;
        if (erased(sector.data(), sector.size())) {
            spare_sector = index;
            break;
        }
    }
    if (spare_sector > kRecordSectors) return AuditResult::Unavailable;
    size_t destination = kDataOffset + spare_sector * kSectorSize;
    for (const StoredRecord& record : records) {
        if ((record.offset - kDataOffset) / kSectorSize == oldest_sector && record.record.id.sequence != records.front().record.id.sequence) {
            result = write_record(destination, record.record);
            if (result != AuditResult::Ok) return result;
            destination += kRecordSize;
        }
    }
    result = write_record(destination, event);
    if (result != AuditResult::Ok) return result;
    return storage_.erase(kDataOffset + oldest_sector * kSectorSize, kSectorSize);
}

AuditResult AuditStore::read_after(AuditCursor after, size_t limit, AuditPage* page)
{
    std::lock_guard<std::mutex> guard(g_lock);
    if (!initialized_ || clearing_ || page == nullptr || limit == 0 || limit > kRecordCapacity) return AuditResult::Invalid;
    if (after.epoch != 0 && after.epoch != epoch_) return AuditResult::Invalid;
    std::vector<StoredRecord> records;
    const AuditResult result = load_records(&records);
    if (result != AuditResult::Ok) return result;
    if (after.sequence != 0) {
        if (records.empty() || after.sequence > records.back().record.id.sequence || after.sequence < records.front().record.id.sequence) return AuditResult::Invalid;
    }
    page->events.clear();
    page->next_after = after;
    page->has_more = false;
    for (const StoredRecord& stored : records) {
        if (stored.record.id.sequence <= after.sequence) continue;
        if (page->events.size() == limit) {
            page->has_more = true;
            break;
        }
        page->events.push_back(stored.record);
        page->next_after = stored.record.id;
    }
    return AuditResult::Ok;
}

AuditResult AuditStore::complete_clear()
{
    for (size_t offset = kDataOffset; offset < kPartitionSize; offset += kSectorSize) {
        const AuditResult result = storage_.erase(offset, kSectorSize);
        if (result != AuditResult::Ok) return result;
    }
    next_sequence_ = reserved_next_;
    return write_metadata(false, epoch_, reserved_next_);
}

AuditResult AuditStore::clear()
{
    std::lock_guard<std::mutex> guard(g_lock);
    if (!initialized_ || clearing_ || epoch_ == UINT32_MAX) return AuditResult::Unavailable;
    AuditResult result = write_metadata(true, epoch_ + 1, reserved_next_);
    if (result != AuditResult::Ok) return result;
    result = complete_clear();
    if (result == AuditResult::Ok) initialized_ = true;
    return result;
}

#ifdef ESP_PLATFORM
EspAuditStorage::EspAuditStorage()
    : partition_(esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "audit")) {}

size_t EspAuditStorage::size() const { return partition_ == nullptr ? 0 : partition_->size; }
AuditResult EspAuditStorage::read(size_t offset, void* data, size_t size) const
{
    return partition_ != nullptr && esp_partition_read(partition_, offset, data, size) == ESP_OK ? AuditResult::Ok : AuditResult::Unavailable;
}
AuditResult EspAuditStorage::write(size_t offset, const void* data, size_t size)
{
    return partition_ != nullptr && esp_partition_write(partition_, offset, data, size) == ESP_OK ? AuditResult::Ok : AuditResult::Unavailable;
}
AuditResult EspAuditStorage::erase(size_t offset, size_t size)
{
    return partition_ != nullptr && esp_partition_erase_range(partition_, offset, size) == ESP_OK ? AuditResult::Ok : AuditResult::Unavailable;
}
#endif

}
