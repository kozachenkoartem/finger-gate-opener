#include "fingerprint_task.hpp"
#include "api_router.hpp"

#include <cstring>
#include <memory>
#include <new>
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/task.h"

namespace fg {
namespace {
constexpr char kLogTag[] = "fingerprint";
constexpr auto kTouchPin = GPIO_NUM_3;
constexpr TickType_t kPollDelay = pdMS_TO_TICKS(10);
constexpr uint64_t kSnapshotIntervalMs = 100;
constexpr uint32_t kTaskStackBytes = 24576;

r558s::LedColor led_color(IndicatorColor color)
{
    switch (color) {
    case IndicatorColor::Off: return r558s::LedColor::Off;
    case IndicatorColor::Blue: return r558s::LedColor::Blue;
    case IndicatorColor::Green: return r558s::LedColor::Green;
    case IndicatorColor::Red: return r558s::LedColor::Red;
    case IndicatorColor::Yellow: return r558s::LedColor::Yellow;
    }
    return r558s::LedColor::Off;
}

SensorReply reply(const r558s::TransactionResult& result)
{
    SensorReply response;
    if (result.status == r558s::TransactionStatus::Success) response.code = SensorCode::Ok;
    else if (result.status == r558s::TransactionStatus::SensorRejected) response.code = SensorCode::Rejected;
    return response;
}

class SensorAdapter final : public FingerprintSensor {
public:
    explicit SensorAdapter(r558s::Driver& driver) : driver_(driver) {}
    SensorReply capture(uint32_t timeout) override
    {
        const auto result = driver_.get_image(timeout);
        auto response = reply(result);
        if (result.status == r558s::TransactionStatus::SensorRejected && result.confirmation_code == 0x02) response.code = SensorCode::NoFinger;
        return response;
    }
    SensorReply convert(uint8_t buffer, uint32_t timeout) override { return reply(driver_.image_to_template(buffer, timeout)); }
    SensorReply create_model(uint32_t timeout) override { return reply(driver_.create_model(timeout)); }
    SensorReply store(uint8_t buffer, uint16_t slot, uint32_t timeout) override { return reply(driver_.store_model(buffer, slot, timeout)); }
    SensorReply erase(uint16_t slot, uint32_t timeout) override { return reply(driver_.delete_model(slot, timeout)); }
    SensorReply search(uint8_t buffer, uint32_t timeout) override
    {
        const auto result = driver_.search_template(buffer, 0, UserRegistry::kSlotCount, timeout);
        auto response = reply(result);
        if (result.status == r558s::TransactionStatus::SensorRejected && result.confirmation_code == 0x09) response.code = SensorCode::NotFound;
        if (response.code == SensorCode::Ok) {
            if (result.data.size() != 4) response.code = SensorCode::Uncertain;
            else {
                response.slot = (static_cast<uint16_t>(result.data[0]) << 8) | result.data[1];
                if (response.slot >= UserRegistry::kSlotCount) response.code = SensorCode::Uncertain;
            }
        }
        if (response.code != SensorCode::Ok && response.code != SensorCode::NotFound) {
            ESP_LOGW(kLogTag, "Search failed: status=%d confirmation=0x%02X data=%u buffer=%u timeout_ms=%lu",
                     static_cast<int>(result.status), result.confirmation_code,
                     static_cast<unsigned>(result.data.size()), buffer, static_cast<unsigned long>(timeout));
        }
        return response;
    }
    SensorReply index(uint32_t timeout) override
    {
        const auto result = driver_.read_index_page(0, timeout);
        auto response = reply(result);
        if (response.code == SensorCode::Ok) {
            if (result.data.size() != 32) response.code = SensorCode::Uncertain;
            else for (uint16_t slot = 0; slot < UserRegistry::kSlotCount; ++slot)
                response.occupied.set(slot, (result.data[slot / 8] & (1U << (slot % 8))) != 0);
        }
        return response;
    }
private:
    r558s::Driver& driver_;
};

class Clock final : public FingerprintClock {
public:
    uint64_t now_ms() const override { return esp_timer_get_time() / 1000; }
};
}

void FingerprintTask::start()
{
    if (gate_.initialize() != ESP_OK) ESP_LOGE(kLogTag, "Gate LED unavailable; access requests will fail inactive");
    indication_queue_ = xQueueCreate(1, sizeof(ProvisioningIndicatorState));
    command_queue_ = xQueueCreate(8, sizeof(QueuedCommand));
    if (!indication_queue_ || !command_queue_ || xTaskCreate(task_entry, "fingerprint", kTaskStackBytes, this, 5, nullptr) != pdPASS) {
        ESP_LOGE(kLogTag, "Fingerprint task unavailable");
        if (command_queue_) { vQueueDelete(command_queue_); command_queue_ = nullptr; }
        if (indication_queue_) { vQueueDelete(indication_queue_); indication_queue_ = nullptr; }
    }
}

void FingerprintTask::set_provisioning(ProvisioningIndicatorState state)
{
    if (indication_queue_) xQueueOverwrite(indication_queue_, &state);
}

uint32_t FingerprintTask::submit(const FingerprintCommand& command)
{
    if (!command_queue_ || command.name.size() > 64) return 0;
    QueuedCommand queued = {};
    queued.id = next_command_id_.fetch_add(1) & 0x7fffffff;
    if (queued.id == 0) queued.id = next_command_id_.fetch_add(1) & 0x7fffffff;
    queued.type = command.type;
    queued.slot = command.slot;
    queued.role = command.role;
    queued.operation_id = command.operation_id;
    queued.source = command.source;
    std::memcpy(queued.name, command.name.data(), command.name.size());
    return xQueueSend(command_queue_, &queued, 0) == pdTRUE ? queued.id : 0;
}

std::string FingerprintTask::snapshot_json()
{
    std::lock_guard<std::mutex> lock(snapshot_mutex_);
    return snapshot_json_;
}

void FingerprintTask::publish(const FingerprintSnapshot& snapshot)
{
    std::string json = "{\"ready\":" + std::string(snapshot.ready ? "true" : "false") + ",\"users\":[";
    bool separator = false;
    for (const auto& user : snapshot.users) {
        if (separator) json += ',';
        separator = true;
        json += "{\"slot\":" + std::to_string(user.slot) + ",\"name\":" + json_quote(user.name) +
                ",\"role\":\"" + (user.role == Role::Master ? "Master" : "User") + "\",\"active\":" +
                (user.active ? "true" : "false") + "}";
    }
    json += "],\"quarantined\":[";
    separator = false;
    for (uint16_t slot = 0; slot < UserRegistry::kSlotCount; ++slot) if (snapshot.quarantined.test(slot)) {
        if (separator) json += ',';
        separator = true;
        json += std::to_string(slot);
    }
    json += "],\"enrollment\":{\"active\":" + std::string(snapshot.enrolling ? "true" : "false") +
        ",\"state\":" + json_quote(snapshot.enrollment_state) + ",\"message\":" + json_quote(snapshot.message) +
        ",\"scan\":" + std::to_string(snapshot.scan) + ",\"slot\":" + std::to_string(snapshot.enrolled_slot) +
        ",\"id\":" + std::to_string(snapshot.operation_id) + "},\"last_access\":" + json_quote(snapshot.last_access) +
        ",\"last_match_slot\":" + std::to_string(snapshot.last_match_slot) + ",\"commands\":[";
    separator = false;
    for (const auto& receipt : receipts_) if (receipt.id) {
        if (separator) json += ',';
        separator = true;
        json += "{\"id\":" + std::to_string(receipt.id) + ",\"result\":" + json_quote(receipt.result) + "}";
    }
    json += "]}";
    std::lock_guard<std::mutex> lock(snapshot_mutex_);
    snapshot_json_ = std::move(json);
}

void FingerprintTask::task_entry(void* context)
{
    static_cast<FingerprintTask*>(context)->run();
    vTaskDelete(nullptr);
}

void FingerprintTask::run()
{
    driver_.initialize();
    SensorAdapter sensor(driver_);
    Clock clock;
    std::unique_ptr<FingerprintController> controller(new (std::nothrow) FingerprintController(storage_, sensor, gate_, clock, audit_));
    if (!controller) { ESP_LOGE(kLogTag, "Controller allocation failed"); return; }
    controller->initialize();
    {
        const auto initial = controller->snapshot();
        ESP_LOGI(kLogTag, "Controller ready=%d, users=%u, quarantined=%u", initial.ready,
                 static_cast<unsigned>(initial.users.size()), static_cast<unsigned>(initial.quarantined.count()));
    }
    IndicatorScheduler indicator;
    IndicatorColor applied = IndicatorColor::Off;
    bool first_led = true;
    uint64_t next_snapshot = 0;
    while (true) {
        ProvisioningIndicatorState provisioning;
        if (xQueueReceive(indication_queue_, &provisioning, 0) == pdTRUE) indicator.set_provisioning(provisioning);
        QueuedCommand queued;
        bool changed = false;
        // Не более одной веб-команды за проход: очередь не вытесняет распознавание.
        if (xQueueReceive(command_queue_, &queued, 0) == pdTRUE) {
            FingerprintCommand command{queued.type, queued.slot, queued.name, queued.role,
                queued.type == FingerprintCommandType::Enroll ? queued.id : queued.operation_id, queued.source};
            const auto result = controller->command(command);
            if (result != "ok") {
                AuditRecord event;
                event.type = queued.type == FingerprintCommandType::Enroll ? AuditType::Enrollment : AuditType::User;
                event.result = AuditResultCode::Failed;
                event.source = queued.source;
                event.slot = queued.slot;
                event.elapsed_ms = clock.now_ms();
                std::memcpy(event.name.data(), queued.name, sizeof(event.name) - 1);
                audit_.publish(event);
            }
            receipts_[receipt_index_++ % receipts_.size()] = {queued.id, result};
            ESP_LOGI(kLogTag, "Audit: command %lu type %d result %s", static_cast<unsigned long>(queued.id), static_cast<int>(queued.type), result.c_str());
            changed = true;
        }
        controller->tick(gpio_get_level(kTouchPin) != 0);
        // Erase-capable storage work runs only between recognition/enrollment steps.
        if (controller->audit_idle()) audit_.drain(1);
        const auto signal = controller->take_signal();
        const auto now = clock.now_ms();
        if (changed || signal != FingerprintSignal::None || now >= next_snapshot) {
            const auto snapshot = controller->snapshot();
            indicator.set_enrollment(snapshot.enrolling);
            if (signal == FingerprintSignal::Success || signal == FingerprintSignal::Failure) {
                indicator.show_result(signal == FingerprintSignal::Success, now);
                ESP_LOGI(kLogTag, "Audit: access %s slot %u enrollment %s", snapshot.last_access.c_str(), snapshot.last_match_slot, snapshot.message.c_str());
            }
            publish(snapshot);
            next_snapshot = now + kSnapshotIntervalMs;
        }
        const auto color = indicator.update(now);
        if (first_led || color != applied) {
            const auto result = driver_.set_led(led_color(color));
            if (result.status == r558s::TransactionStatus::Success) { applied = color; first_led = false; }
            else ESP_LOGE(kLogTag, "LED command failed: %d", static_cast<int>(result.status));
        }
        vTaskDelay(kPollDelay);
    }
}
}
