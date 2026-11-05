#include "hub_auth.hpp"

#include <algorithm>
#include <cstring>

#include "auth_crypto.hpp"

#ifdef ESP_PLATFORM
#include "mbedtls/sha256.h"
#else
#include <openssl/sha.h>
#endif

namespace fg {
namespace {
constexpr char kAuthKey[] = "hub_auth";
constexpr char kLedgerKey[] = "hub_ledger";
constexpr uint32_t kAuthMagic = 0x46474841;
constexpr uint32_t kLedgerMagic = 0x46474c47;
constexpr uint16_t kFormatVersion = 1;
constexpr uint16_t kLedgerFormatVersion = 2;
constexpr size_t kLedgerCapacity = 16;
constexpr uint32_t kMaxFailedAuthorizations = 5;
constexpr uint64_t kAuthorizationWindowMs = 60000;

struct AuthPersisted {
    uint32_t magic = kAuthMagic;
    uint16_t version = kFormatVersion;
    uint16_t active = 0;
    uint32_t generation = 0;
    std::array<uint8_t, 32> verifier{};
};

struct LedgerEntry {
    std::array<char, 65> request_id{};
    HubCommandState state = HubCommandState::Reserved;
    uint64_t terminal_order = 0;
};

struct LegacyLedgerEntry {
    std::array<char, 65> request_id{};
    HubCommandState state = HubCommandState::Reserved;
};

struct LegacyLedgerPersisted {
    uint32_t magic = kLedgerMagic;
    uint16_t version = kFormatVersion;
    uint16_t reserved = 0;
    std::array<LegacyLedgerEntry, kLedgerCapacity> entries{};
};

bool sha256(std::string_view value, std::array<uint8_t, 32>* output)
{
#ifdef ESP_PLATFORM
    return mbedtls_sha256(reinterpret_cast<const unsigned char*>(value.data()), value.size(), output->data(), 0) == 0;
#else
    return SHA256(reinterpret_cast<const unsigned char*>(value.data()), value.size(), output->data()) != nullptr;
#endif
}

bool terminal(HubCommandState state)
{
    return state == HubCommandState::Granted || state == HubCommandState::Rejected ||
           state == HubCommandState::Interrupted || state == HubCommandState::Cancelled || state == HubCommandState::Failed;
}
}

struct HubCommandLedger::Persisted {
    uint32_t magic = kLedgerMagic;
    uint16_t version = kLedgerFormatVersion;
    uint16_t reserved = 0;
    uint64_t next_terminal_order = 1;
    std::array<LedgerEntry, kLedgerCapacity> entries{};
};

HubLedgerResult HubCommandLedger::load_locked()
{
    if (loaded_) return HubLedgerResult::Ok;
    std::vector<uint8_t> bytes;
    const StoreResult result = storage_.get(kLedgerKey, &bytes);
    persisted_ = new Persisted;
    if (result == StoreResult::NotFound) {
        loaded_ = true;
        return save_locked();
    }
    if (result != StoreResult::Ok) return HubLedgerResult::Unavailable;
    bool migrated = false;
    if (bytes.size() == sizeof(Persisted)) {
        std::memcpy(persisted_, bytes.data(), sizeof(Persisted));
        if (persisted_->magic != kLedgerMagic || persisted_->version != kLedgerFormatVersion) return HubLedgerResult::Unavailable;
    } else if (bytes.size() == sizeof(LegacyLedgerPersisted)) {
        LegacyLedgerPersisted legacy;
        std::memcpy(&legacy, bytes.data(), sizeof(legacy));
        if (legacy.magic != kLedgerMagic || legacy.version != kFormatVersion) return HubLedgerResult::Unavailable;
        for (size_t index = 0; index < legacy.entries.size(); ++index) {
            persisted_->entries[index].request_id = legacy.entries[index].request_id;
            persisted_->entries[index].state = legacy.entries[index].state;
            if (legacy.entries[index].request_id[0] && terminal(legacy.entries[index].state))
                persisted_->entries[index].terminal_order = persisted_->next_terminal_order++;
        }
        migrated = true;
    } else {
        return HubLedgerResult::Unavailable;
    }
    loaded_ = true;
    bool interrupted = false;
    for (auto& entry : persisted_->entries) if (entry.request_id[0] && !terminal(entry.state)) {
        entry.state = HubCommandState::Interrupted;
        entry.terminal_order = persisted_->next_terminal_order++;
        interrupted = true;
    }
    return (interrupted || migrated) ? save_locked() : HubLedgerResult::Ok;
}

HubLedgerResult HubCommandLedger::save_locked()
{
    const std::vector<uint8_t> bytes(reinterpret_cast<const uint8_t*>(persisted_), reinterpret_cast<const uint8_t*>(persisted_) + sizeof(Persisted));
    return storage_.put(kLedgerKey, bytes) == StoreResult::Ok ? HubLedgerResult::Ok : HubLedgerResult::Unavailable;
}

bool HubCommandLedger::valid_request_id(std::string_view request_id)
{
    return request_id.size() >= 16 && request_id.size() <= 64 && std::all_of(request_id.begin(), request_id.end(), [](char c) {
        return c >= 0x21 && c <= 0x7e;
    });
}

int HubCommandLedger::find_locked(std::string_view request_id) const
{
    for (size_t index = 0; index < persisted_->entries.size(); ++index) {
        const auto& entry = persisted_->entries[index];
        if (entry.request_id[0] && request_id == entry.request_id.data()) return static_cast<int>(index);
    }
    return -1;
}

HubLedgerResult HubCommandLedger::initialize()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return load_locked();
}

HubLedgerResult HubCommandLedger::reserve(std::string_view request_id)
{
    if (!valid_request_id(request_id)) return HubLedgerResult::Invalid;
    std::lock_guard<std::mutex> lock(mutex_);
    if (load_locked() != HubLedgerResult::Ok) return HubLedgerResult::Unavailable;
    if (find_locked(request_id) >= 0) return HubLedgerResult::Duplicate;
    auto entry = std::find_if(persisted_->entries.begin(), persisted_->entries.end(), [](const LedgerEntry& item) { return !item.request_id[0]; });
    if (entry == persisted_->entries.end()) {
        entry = std::find_if(persisted_->entries.begin(), persisted_->entries.end(), [](const LedgerEntry& item) { return terminal(item.state); });
        if (entry != persisted_->entries.end()) {
            for (auto candidate = entry + 1; candidate != persisted_->entries.end(); ++candidate)
                if (terminal(candidate->state) && candidate->terminal_order < entry->terminal_order) entry = candidate;
        }
    }
    if (entry == persisted_->entries.end()) return HubLedgerResult::Full;
    *entry = {};
    std::memcpy(entry->request_id.data(), request_id.data(), request_id.size());
    entry->state = HubCommandState::Reserved;
    return save_locked();
}

HubLedgerResult HubCommandLedger::mark_executable(std::string_view request_id)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (load_locked() != HubLedgerResult::Ok) return HubLedgerResult::Unavailable;
    const int index = find_locked(request_id);
    if (index < 0) return HubLedgerResult::NotFound;
    auto& entry = persisted_->entries[index];
    if (entry.state != HubCommandState::Reserved) return HubLedgerResult::Duplicate;
    entry.state = HubCommandState::Executable;
    return save_locked();
}

HubLedgerResult HubCommandLedger::begin_execution(std::string_view request_id)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (load_locked() != HubLedgerResult::Ok) return HubLedgerResult::Unavailable;
    const int index = find_locked(request_id);
    if (index < 0) return HubLedgerResult::NotFound;
    auto& entry = persisted_->entries[index];
    if (entry.state != HubCommandState::Executable) return HubLedgerResult::Duplicate;
    entry.state = HubCommandState::Running;
    return save_locked();
}

HubLedgerResult HubCommandLedger::cancel_unstarted()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (load_locked() != HubLedgerResult::Ok) return HubLedgerResult::Unavailable;
    bool changed = false;
    for (auto& entry : persisted_->entries) if (entry.request_id[0] &&
        (entry.state == HubCommandState::Reserved || entry.state == HubCommandState::Executable)) {
        entry.state = HubCommandState::Cancelled;
        entry.terminal_order = persisted_->next_terminal_order++;
        changed = true;
    }
    return changed ? save_locked() : HubLedgerResult::Ok;
}

HubLedgerResult HubCommandLedger::complete(std::string_view request_id, HubCommandState result)
{
    if (!terminal(result)) return HubLedgerResult::Invalid;
    std::lock_guard<std::mutex> lock(mutex_);
    if (load_locked() != HubLedgerResult::Ok) return HubLedgerResult::Unavailable;
    const int index = find_locked(request_id);
    if (index < 0) return HubLedgerResult::NotFound;
    auto& entry = persisted_->entries[index];
    if (entry.state != HubCommandState::Running && !(result == HubCommandState::Failed &&
        (entry.state == HubCommandState::Reserved || entry.state == HubCommandState::Executable))) return HubLedgerResult::Duplicate;
    entry.state = result;
    entry.terminal_order = persisted_->next_terminal_order++;
    return save_locked();
}

HubLedgerResult HubCommandLedger::get(std::string_view request_id, HubCommand* command) const
{
    if (!command) return HubLedgerResult::Invalid;
    std::lock_guard<std::mutex> lock(mutex_);
    if (const_cast<HubCommandLedger*>(this)->load_locked() != HubLedgerResult::Ok) return HubLedgerResult::Unavailable;
    const int index = find_locked(request_id);
    if (index < 0) return HubLedgerResult::NotFound;
    command->request_id = persisted_->entries[index].request_id.data();
    command->state = persisted_->entries[index].state;
    return HubLedgerResult::Ok;
}

HubAuthResult HubAuth::load_locked()
{
    if (loaded_) return HubAuthResult::Ok;
    std::vector<uint8_t> bytes;
    const StoreResult result = storage_.get(kAuthKey, &bytes);
    if (result == StoreResult::NotFound) { loaded_ = true; return HubAuthResult::Ok; }
    if (result != StoreResult::Ok || bytes.size() != sizeof(AuthPersisted)) return HubAuthResult::Unavailable;
    AuthPersisted persisted;
    std::memcpy(&persisted, bytes.data(), sizeof(persisted));
    if (persisted.magic != kAuthMagic || persisted.version != kFormatVersion) return HubAuthResult::Unavailable;
    active_ = persisted.active == 1;
    generation_ = persisted.generation;
    verifier_ = persisted.verifier;
    loaded_ = true;
    return HubAuthResult::Ok;
}

HubAuthResult HubAuth::save_locked()
{
    const AuthPersisted persisted{kAuthMagic, kFormatVersion, static_cast<uint16_t>(active_), generation_, verifier_};
    const std::vector<uint8_t> bytes(reinterpret_cast<const uint8_t*>(&persisted), reinterpret_cast<const uint8_t*>(&persisted) + sizeof(persisted));
    return storage_.put(kAuthKey, bytes) == StoreResult::Ok ? HubAuthResult::Ok : HubAuthResult::Unavailable;
}

HubAuthResult HubAuth::create_or_rotate(std::string* token)
{
    if (!token) return HubAuthResult::Unavailable;
    std::lock_guard<std::mutex> lock(mutex_);
    if (load_locked() != HubAuthResult::Ok || !auth_crypto::random_secret(token) || !sha256(*token, &verifier_)) return HubAuthResult::Unavailable;
    active_ = true;
    ++generation_;
    const HubAuthResult result = save_locked();
    if (result == HubAuthResult::Ok && ledger_ && ledger_->cancel_unstarted() != HubLedgerResult::Ok) return HubAuthResult::Unavailable;
    return result;
}

HubAuthResult HubAuth::revoke()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (load_locked() != HubAuthResult::Ok) return HubAuthResult::Unavailable;
    active_ = false;
    auth_crypto::wipe(verifier_.data(), verifier_.size());
    ++generation_;
    const HubAuthResult result = save_locked();
    if (result == HubAuthResult::Ok && ledger_ && ledger_->cancel_unstarted() != HubLedgerResult::Ok) return HubAuthResult::Unavailable;
    return result;
}

HubAuthResult HubAuth::authorize_bearer(std::string_view header, uint64_t now_ms)
{
    constexpr std::string_view kPrefix = "Bearer ";
    std::array<uint8_t, 32> candidate{};
    const bool well_formed = header.substr(0, kPrefix.size()) == kPrefix && header.size() == kPrefix.size() + 64 &&
        std::all_of(header.begin() + std::min(header.size(), kPrefix.size()), header.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        });
    if (well_formed && !sha256(header.substr(kPrefix.size()), &candidate)) return HubAuthResult::Unavailable;
    std::lock_guard<std::mutex> lock(mutex_);
    const HubAuthResult loaded = load_locked();
    const bool matches = well_formed && active_ && auth_crypto::constant_time_equal(candidate.data(), verifier_.data(), verifier_.size());
    auth_crypto::wipe(candidate.data(), candidate.size());
    if (loaded != HubAuthResult::Ok) return loaded;
    if (matches) { failed_attempts_ = 0; return HubAuthResult::Ok; }
    if (now_ms != 0) {
        if (now_ms < failed_window_started_ms_ || now_ms - failed_window_started_ms_ >= kAuthorizationWindowMs) {
            failed_window_started_ms_ = now_ms;
            failed_attempts_ = 0;
        }
        if (failed_attempts_ >= kMaxFailedAuthorizations) return HubAuthResult::RateLimited;
        ++failed_attempts_;
    }
    return well_formed ? HubAuthResult::Unauthorized : HubAuthResult::Malformed;
}

HubLedgerResult HubAuth::begin_execution(std::string_view request_id)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (load_locked() != HubAuthResult::Ok || !active_ || !ledger_) return HubLedgerResult::Unavailable;
    return ledger_->begin_execution(request_id);
}

uint32_t HubAuth::generation() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return const_cast<HubAuth*>(this)->load_locked() == HubAuthResult::Ok ? generation_ : 0;
}

}
