#pragma once

#include <atomic>
#include <mutex>
#include <string>

#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "fingerprint_task.hpp"
#include "wifi_event_gate.hpp"
#include "wifi_lifecycle.hpp"
#include "network_requests.hpp"

namespace fg {
class Provisioning final : private NetworkPort {
public:
    Provisioning(KeyValueStore& storage, FingerprintTask& fingerprint_task)
        : storage_(storage), fingerprint_task_(fingerprint_task), lifecycle_(storage, *this) {}
    esp_err_t start();
    void poll();
    std::string status_json();
    const std::string& hostname() const { return hostname_; }
    uint32_t reserve(NetworkOperation operation, const WifiCredentials& credentials = {}, const std::string& password = {});
    void finish_response(uint32_t id, bool sent);

private:
    enum class EventType { Associated, Disconnected, Ip };
    struct Event {
        EventType type;
        uint32_t sequence;
        char ssid[33] = {};
        std::array<uint8_t,6> bssid{};
        char ip[16] = {};
    };

    static void event_handler(void*, esp_event_base_t, int32_t, void*);
    static esp_err_t setup_page_handler(httpd_req_t* request);
    esp_err_t start_http_server();
    bool open_ap(const std::string& password) override;
    bool close_ap() override;
    bool connect(const WifiCredentials& credentials, uint32_t attempt) override;
    bool disconnect() override;
    bool ap_restarted_station() const override { return radio_restarted_; }
    bool configure_ap(const std::string& password);
    void service_link(uint64_t now);
    void publish();
    void process_event(const Event& event);

    esp_netif_t* ap_netif_ = nullptr;
    httpd_handle_t server_ = nullptr;
    KeyValueStore& storage_;
    FingerprintTask& fingerprint_task_;
    WifiLifecycle lifecycle_;
    WifiEventGate link_;
    QueueHandle_t events_ = nullptr;
    std::atomic<uint32_t> event_sequence_{0};
    std::atomic<bool> event_overflow_{false};
    WifiCredentials target_;
    std::string configured_ap_password_;
    std::string hostname_;
    std::string ap_ssid_;
    uint64_t disconnect_deadline_ = 0;
    bool radio_restarted_ = false;
    bool radio_running_ = false;
    bool station_idle_ = true;
    bool start_pending_ = false;
    uint64_t next_snapshot_ = 0;
    std::mutex mutex_;
    NetworkRequests requests_;
    WifiStatus cached_;
    std::string snapshot_ = "{\"state\":\"initializing\"}";
};
}
