#include "provisioning.hpp"
#include "api_router.hpp"

#include <cstdio>
#include <cstring>
#include <algorithm>
#include "esp_check.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "lwip/ip4_addr.h"

namespace fg {
namespace {
constexpr char kLogTag[] = "provisioning";
constexpr uint64_t kDisconnectWaitMs = 2000;
constexpr uint64_t kSnapshotIntervalMs = 200;
constexpr char kSetupPage[] =
    "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>Finger Gate Setup</title><h1>Finger Gate</h1>"
    "<p><a href='https://192.168.4.1/'>Open HTTPS administration</a></p>"
    "<p>Use your administrator password. Initial login: admin / admin.</p>";

uint64_t now_ms() { return esp_timer_get_time() / 1000; }

const char* result_name(NetworkResult result)
{
    switch (result) {
    case NetworkResult::Ok: return "ok";
    case NetworkResult::Busy: return "busy";
    case NetworkResult::Invalid: return "invalid_input";
    case NetworkResult::StorageFailed: return "storage_failed";
    case NetworkResult::DriverFailed: return "driver_failed";
    case NetworkResult::NotReady: return "not_ready";
    }
    return "failed";
}
}

esp_err_t Provisioning::start()
{
    bool custom = false;
    std::string ap_password;
    if (ConfigStore(storage_).load_ap_password(&ap_password, &custom) != StoreResult::Ok) return ESP_FAIL;
    ESP_RETURN_ON_ERROR(esp_netif_init(), kLogTag, "network initialization failed");
    ESP_RETURN_ON_ERROR(esp_event_loop_create_default(), kLogTag, "event loop initialization failed");
    ap_netif_ = esp_netif_create_default_wifi_ap();
    if (!ap_netif_ || !esp_netif_create_default_wifi_sta()) return ESP_ERR_NO_MEM;
    const auto dhcp_stop = esp_netif_dhcps_stop(ap_netif_);
    if (dhcp_stop != ESP_OK && dhcp_stop != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) {
        ESP_LOGE(kLogTag, "DHCP stop failed: %s", esp_err_to_name(dhcp_stop));
        return dhcp_stop;
    }
    esp_netif_ip_info_t ip = {};
    IP4_ADDR(&ip.ip, 192, 168, 4, 1);
    IP4_ADDR(&ip.gw, 192, 168, 4, 1);
    IP4_ADDR(&ip.netmask, 255, 255, 255, 0);
    ESP_RETURN_ON_ERROR(esp_netif_set_ip_info(ap_netif_, &ip), kLogTag, "AP IP failed");
    ESP_RETURN_ON_ERROR(esp_netif_dhcps_start(ap_netif_), kLogTag, "DHCP start failed");
    uint8_t mac[6] = {};
    ESP_RETURN_ON_ERROR(esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP), kLogTag, "MAC read failed");
    char hostname[sizeof("finger-gate-0000")] = {};
    char ssid[sizeof("FingerGate-0000")] = {};
    std::snprintf(hostname, sizeof(hostname), "finger-gate-%02x%02x", mac[4], mac[5]);
    std::snprintf(ssid, sizeof(ssid), "FingerGate-%02X%02X", mac[4], mac[5]);
    hostname_ = hostname;
    ap_ssid_ = ssid;
    events_ = xQueueCreate(32, sizeof(Event));
    if (!events_) return ESP_ERR_NO_MEM;
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_RETURN_ON_ERROR(esp_wifi_init(&init), kLogTag, "Wi-Fi initialization failed");
    ESP_RETURN_ON_ERROR(esp_wifi_set_storage(WIFI_STORAGE_RAM), kLogTag, "Wi-Fi RAM storage failed");
    ESP_RETURN_ON_ERROR(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, event_handler, this, nullptr), kLogTag, "Wi-Fi handler failed");
    ESP_RETURN_ON_ERROR(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, event_handler, this, nullptr), kLogTag, "IP handler failed");
    // Готовим защищённый AP до запуска радио: открытая сеть не объявляется даже кратко.
    ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_APSTA), kLogTag, "initial mode failed");
    if (!configure_ap(ap_password)) return ESP_FAIL;
    ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA), kLogTag, "station mode failed");
    ESP_RETURN_ON_ERROR(esp_wifi_start(), kLogTag, "Wi-Fi start failed");
    radio_running_ = true;
    if (!lifecycle_.initialize(now_ms())) return ESP_FAIL;
    publish();
    return ESP_OK;
}

bool Provisioning::configure_ap(const std::string& password)
{
    wifi_config_t config = {};
    std::memcpy(config.ap.ssid, ap_ssid_.data(), ap_ssid_.size());
    std::memcpy(config.ap.password, password.data(), password.size());
    config.ap.ssid_len = ap_ssid_.size();
    config.ap.max_connection = 4;
    config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    if (esp_wifi_set_config(WIFI_IF_AP, &config) != ESP_OK) return false;
    configured_ap_password_ = password;
    return true;
}

bool Provisioning::open_ap(const std::string& password)
{
    radio_restarted_ = password != configured_ap_password_;
    if (radio_restarted_) {
        link_.invalidate();
        if (esp_wifi_stop() != ESP_OK) return false;
        radio_running_ = false;
        station_idle_ = true;
        if (esp_wifi_set_mode(WIFI_MODE_APSTA) != ESP_OK || !configure_ap(password) || esp_wifi_start() != ESP_OK) {
            esp_wifi_set_mode(WIFI_MODE_STA);
            radio_running_ = esp_wifi_start() == ESP_OK;
            return false;
        }
        radio_running_ = true;
    } else if (esp_wifi_set_mode(WIFI_MODE_APSTA) != ESP_OK) return false;
    if (!radio_running_) {
        if (esp_wifi_start() != ESP_OK) return false;
        radio_running_ = true;
        station_idle_ = true;
        radio_restarted_ = true;
    }
    if (start_http_server() != ESP_OK) ESP_LOGW(kLogTag, "HTTP landing unavailable; use HTTPS at 192.168.4.1");
    ESP_LOGI(kLogTag, "Protected AP enabled: %s", ap_ssid_.c_str());
    return true;
}

bool Provisioning::close_ap()
{
    if (server_) {
        if (httpd_stop(server_) != ESP_OK) return false;
        server_ = nullptr;
    }
    if (esp_wifi_set_mode(WIFI_MODE_STA) != ESP_OK) return false;
    ESP_LOGI(kLogTag, "AP stopped; station lifecycle continues");
    return true;
}

bool Provisioning::connect(const WifiCredentials& credentials, uint32_t attempt)
{
    if (!radio_running_) {
        if (esp_wifi_start() != ESP_OK) return false;
        radio_running_ = true;
        station_idle_ = true;
    }
    target_ = credentials;
    start_pending_ = true;
    link_.begin(attempt, credentials.ssid, event_sequence_.load());
    disconnect_deadline_ = now_ms() + kDisconnectWaitMs;
    const auto result = esp_wifi_disconnect();
    wifi_ap_record_t ap = {};
    if (result == ESP_ERR_WIFI_NOT_CONNECT || (result == ESP_OK && station_idle_ &&
        esp_wifi_sta_get_ap_info(&ap) == ESP_ERR_WIFI_NOT_CONNECT)) {
        station_idle_ = true;
        link_.disconnected_already(event_sequence_.load());
    }
    else if (result != ESP_OK) { link_.invalidate(); return false; }
    return true;
}

bool Provisioning::disconnect()
{
    start_pending_ = false;
    link_.begin(link_.attempt(), target_.ssid, event_sequence_.load());
    const auto result = esp_wifi_disconnect();
    if (result == ESP_ERR_WIFI_NOT_CONNECT) { station_idle_ = true; link_.invalidate(); }
    return result == ESP_OK || result == ESP_ERR_WIFI_NOT_CONNECT;
}

void Provisioning::service_link(uint64_t now)
{
    if (start_pending_ && link_.disconnecting() && now >= disconnect_deadline_) {
        const auto attempt = link_.attempt();
        link_.invalidate();
        start_pending_ = false;
        // Потерянное событие отключения не оставляет автомат в вечном ожидании.
        if (esp_wifi_stop() == ESP_OK) {
            radio_running_ = false;
            station_idle_ = true;
            radio_running_ = esp_wifi_start() == ESP_OK;
        }
        lifecycle_.disconnected(attempt, now);
        return;
    }
    if (!start_pending_ || !link_.ready()) return;
    wifi_config_t config = {};
    std::memcpy(config.sta.ssid, target_.ssid.data(), target_.ssid.size());
    std::memcpy(config.sta.password, target_.password.data(), target_.password.size());
    const auto attempt = link_.attempt();
    // Все ранее поставленные события отделены границей до новой ассоциации.
    link_.started(event_sequence_.load());
    start_pending_ = false;
    station_idle_ = false;
    if (esp_wifi_set_config(WIFI_IF_STA, &config) != ESP_OK || esp_wifi_connect() != ESP_OK) {
        link_.invalidate();
        lifecycle_.disconnected(attempt, now);
    }
}

esp_err_t Provisioning::start_http_server()
{
    if (server_) return ESP_OK;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    ESP_RETURN_ON_ERROR(httpd_start(&server_, &config), kLogTag, "HTTP start failed");
    const httpd_uri_t page = {.uri = "/", .method = HTTP_GET, .handler = setup_page_handler, .user_ctx = this};
    const auto result = httpd_register_uri_handler(server_, &page);
    if (result != ESP_OK) { httpd_stop(server_); server_ = nullptr; }
    return result;
}

esp_err_t Provisioning::setup_page_handler(httpd_req_t* request)
{
    httpd_resp_set_type(request, "text/html; charset=utf-8");
    httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    return httpd_resp_sendstr(request, kSetupPage);
}

std::string Provisioning::status_json()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return snapshot_;
}

uint32_t Provisioning::reserve(NetworkOperation operation, const WifiCredentials& credentials, const std::string& password)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return requests_.reserve(operation, credentials, password, cached_);
}

void Provisioning::finish_response(uint32_t id, bool sent)
{
    std::lock_guard<std::mutex> lock(mutex_);
    requests_.finish_response(id, sent, now_ms());
}

void Provisioning::publish()
{
    const auto& status = lifecycle_.status();
    fingerprint_task_.set_provisioning({status.indication, status.ap_active});
    const uint64_t now = now_ms();
    std::string json = "{\"state\":" + json_quote(status.state) + ",\"message\":" + json_quote(status.message) +
        ",\"sta_ip\":" + json_quote(status.sta_ip) + ",\"ssid\":" + json_quote(status.ssid) +
        ",\"hostname\":" + json_quote(hostname_) + ",\"ap_ip\":" + json_quote(status.ap_active ? "192.168.4.1" : "") +
        ",\"ap_ssid\":" + json_quote(ap_ssid_) + ",\"ap_active\":" + (status.ap_active ? "true" : "false") +
        ",\"recovery\":" + (status.recovery ? "true" : "false") + ",\"trial\":" + (status.trial ? "true" : "false") +
        ",\"ap_closing\":" + (status.ap_closing ? "true" : "false") +
        ",\"last_trial\":" + json_quote(status.last_trial) + ",\"ap_password_custom\":" + (status.custom_ap_password ? "true" : "false") +
        ",\"ap_remaining_ms\":" + std::to_string(status.ap_deadline_ms > now ? status.ap_deadline_ms - now : 0);
    std::lock_guard<std::mutex> lock(mutex_);
    cached_ = status;
    snapshot_ = json + ",\"network_command\":{\"id\":" + std::to_string(requests_.last_id()) +
        ",\"result\":" + json_quote(requests_.last_result()) + "}}";
}

void Provisioning::process_event(const Event& event)
{
    if (event.type == EventType::Associated) link_.associated(event.sequence, event.ssid, event.bssid);
    else if (event.type == EventType::Disconnected) {
        const auto attempt = link_.attempt();
        const auto loss = link_.disconnected(event.sequence, event.ssid, event.bssid);
        if (loss != LinkLoss::Ignore) station_idle_ = true;
        if (loss == LinkLoss::Boundary && !start_pending_) link_.invalidate();
        if (loss == LinkLoss::Connection)
            lifecycle_.disconnected(attempt, now_ms());
    } else {
        wifi_ap_record_t ap = {};
        if (esp_wifi_sta_get_ap_info(&ap) != ESP_OK) return;
        std::array<uint8_t,6> bssid{};
        std::memcpy(bssid.data(), ap.bssid, bssid.size());
        const auto attempt = link_.ip(event.sequence, bssid);
        if (attempt && !event_overflow_.load()) {
            lifecycle_.got_ip(attempt, event.ip, now_ms());
            ESP_LOGI(kLogTag, "Station result: %s", lifecycle_.status().message.c_str());
        }
    }
}

void Provisioning::poll()
{
    if (event_overflow_.exchange(false)) {
        Event dropped;
        while (xQueueReceive(events_, &dropped, 0) == pdTRUE) {}
        link_.invalidate();
        lifecycle_.event_loss(now_ms());
    }
    Event event;
    for (unsigned budget = 0; budget < 8 && xQueueReceive(events_, &event, 0) == pdTRUE; ++budget) {
        if (event_overflow_.load()) break;
        process_event(event);
    }
    service_link(now_ms());
    lifecycle_.poll(now_ms());
    NetworkRequest command;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto ready = requests_.take(now_ms());
        if (ready) command = *ready;
    }
    if (command.id) {
        NetworkResult result = NetworkResult::Invalid;
        switch (command.operation) {
        case NetworkOperation::Recovery: result = lifecycle_.open_recovery(now_ms()); break;
        case NetworkOperation::Configure: result = lifecycle_.configure_wifi({command.ssid, command.password}, now_ms()); break;
        case NetworkOperation::ApPassword: result = lifecycle_.set_ap_password(command.password); break;
        case NetworkOperation::Acknowledge: result = lifecycle_.acknowledge(now_ms()); break;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        requests_.completed(command.id, result_name(result));
        ESP_LOGI(kLogTag, "Audit: network command %lu result %s", static_cast<unsigned long>(command.id), result_name(result));
    }
    if (command.id || now_ms() >= next_snapshot_) { publish(); next_snapshot_ = now_ms() + kSnapshotIntervalMs; }
}

void Provisioning::event_handler(void* context, esp_event_base_t base, int32_t id, void* data)
{
    auto* owner = static_cast<Provisioning*>(context);
    Event event{};
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_CONNECTED) {
        event.type = EventType::Associated;
        const auto* connected = static_cast<const wifi_event_sta_connected_t*>(data);
        std::memcpy(event.ssid, connected->ssid, std::min<size_t>(connected->ssid_len, 32));
        std::memcpy(event.bssid.data(), connected->bssid, event.bssid.size());
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        event.type = EventType::Disconnected;
        const auto* disconnected = static_cast<const wifi_event_sta_disconnected_t*>(data);
        std::memcpy(event.ssid, disconnected->ssid, std::min<size_t>(disconnected->ssid_len, 32));
        std::memcpy(event.bssid.data(), disconnected->bssid, event.bssid.size());
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        event.type = EventType::Ip;
        esp_ip4addr_ntoa(&static_cast<const ip_event_got_ip_t*>(data)->ip_info.ip, event.ip, sizeof(event.ip));
    } else return;
    event.sequence = owner->event_sequence_.fetch_add(1) + 1;
    if (xQueueSend(owner->events_, &event, 0) != pdTRUE) owner->event_overflow_.store(true);
}
}
