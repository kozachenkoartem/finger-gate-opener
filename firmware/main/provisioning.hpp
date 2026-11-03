#pragma once

#include <mutex>
#include <string>

#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_netif.h"
#include "fingerprint_task.hpp"
#include "provisioning_state.hpp"
#include "user_store.hpp"

namespace fg {

class Provisioning {
public:
    Provisioning(KeyValueStore& storage, FingerprintTask& fingerprint_task)
        : storage_(storage), fingerprint_task_(fingerprint_task) {}
    esp_err_t start();
    void poll();
    std::string status_json();
    const std::string& hostname() const { return hostname_; }
    esp_err_t configure_wifi(const WifiCredentials& credentials);
    esp_err_t acknowledge(bool schedule_shutdown = true);

private:
    static void event_handler(void*, esp_event_base_t, int32_t, void*);
    static esp_err_t setup_page_handler(httpd_req_t* request);
    esp_err_t start_http_server();
    esp_err_t start_access_point(const uint8_t mac[6]);
    void notify_indicator(ProvisioningIndication indication);
    void on_event(esp_event_base_t, int32_t, void*);

    esp_netif_t* ap_netif_ = nullptr;
    httpd_handle_t server_ = nullptr;
    KeyValueStore& storage_;
    FingerprintTask& fingerprint_task_;
    std::mutex mutex_;
    ProvisioningState state_{"192.168.4.1", "finger-gate"};
    std::string hostname_;
    WifiCredentials pending_credentials_;
    bool access_point_active_ = false;
    bool pending_save_ = false;
    bool station_configured_ = false;
    bool connecting_ = false;
    uint64_t attempt_deadline_ = 0;
    uint64_t shutdown_deadline_ = 0;
    uint64_t reconnect_at_ = 0;
};

}
