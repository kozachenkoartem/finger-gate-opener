#include "provisioning.hpp"
#include "config_store.hpp"

#include <cstdio>
#include <cstring>

#include "esp_check.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "lwip/ip4_addr.h"

namespace fg {
namespace {
constexpr char kLogTag[] = "provisioning";
constexpr char kApPassword[] = "fingergate";
constexpr uint64_t kShutdownDelayMs = 5 * 60 * 1000;
constexpr uint64_t kAcknowledgementDelayMs = 500;
constexpr uint64_t kAttemptTimeoutMs = 30000;
constexpr uint64_t kReconnectDelayMs = 5000;
constexpr char kSetupPage[] =
    "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>Finger Gate Setup</title><h1>Finger Gate</h1>"
    "<p>Secure setup: <a href='https://192.168.4.1/'>Open HTTPS administration</a></p>"
    "<p>Initial login: admin / admin. Change the password before configuring Wi-Fi.</p>";

uint64_t now_ms() { return esp_timer_get_time() / 1000; }

wifi_config_t station_config(const WifiCredentials& credentials)
{
    wifi_config_t config = {};
    std::memcpy(config.sta.ssid, credentials.ssid.data(), credentials.ssid.size());
    std::memcpy(config.sta.password, credentials.password.data(), credentials.password.size());
    return config;
}
}

esp_err_t Provisioning::start()
{
    ESP_RETURN_ON_ERROR(esp_netif_init(), kLogTag, "network initialization failed");
    ESP_RETURN_ON_ERROR(esp_event_loop_create_default(), kLogTag, "event loop initialization failed");
    ap_netif_ = esp_netif_create_default_wifi_ap();
    if (!ap_netif_ || !esp_netif_create_default_wifi_sta()) return ESP_ERR_NO_MEM;
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_RETURN_ON_ERROR(esp_wifi_init(&init), kLogTag, "Wi-Fi initialization failed");
    ESP_RETURN_ON_ERROR(esp_wifi_set_storage(WIFI_STORAGE_RAM), kLogTag, "Wi-Fi RAM storage failed");
    ESP_RETURN_ON_ERROR(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, event_handler, this, nullptr), kLogTag, "Wi-Fi handler failed");
    ESP_RETURN_ON_ERROR(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, event_handler, this, nullptr), kLogTag, "IP handler failed");
    uint8_t mac[6] = {};
    ESP_RETURN_ON_ERROR(esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP), kLogTag, "MAC read failed");
    char hostname[sizeof("finger-gate-0000")] = {};
    std::snprintf(hostname, sizeof(hostname), "finger-gate-%02x%02x", mac[4], mac[5]);
    hostname_ = hostname;
    state_.set_network_details("192.168.4.1", hostname_);
    WifiCredentials credentials;
    const StoreResult loaded = ConfigStore(storage_).load_wifi(&credentials);
    if (loaded == StoreResult::Ok) {
        wifi_config_t config = station_config(credentials);
        ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA), kLogTag, "station mode failed");
        ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_STA, &config), kLogTag, "station config failed");
        state_.connecting();
        station_configured_ = true;
        connecting_ = true;
        attempt_deadline_ = now_ms() + kAttemptTimeoutMs;
        notify_indicator(ProvisioningIndication::Connecting);
        ESP_RETURN_ON_ERROR(esp_wifi_start(), kLogTag, "Wi-Fi start failed");
        return esp_wifi_connect();
    }
    if (!should_start_provisioning(loaded)) return ESP_FAIL;
    return start_access_point(mac);
}

esp_err_t Provisioning::start_access_point(const uint8_t mac[6])
{
    ESP_RETURN_ON_ERROR(esp_netif_dhcps_stop(ap_netif_), kLogTag, "DHCP stop failed");
    esp_netif_ip_info_t ip = {};
    IP4_ADDR(&ip.ip, 192, 168, 4, 1);
    IP4_ADDR(&ip.gw, 192, 168, 4, 1);
    IP4_ADDR(&ip.netmask, 255, 255, 255, 0);
    ESP_RETURN_ON_ERROR(esp_netif_set_ip_info(ap_netif_, &ip), kLogTag, "AP IP failed");
    ESP_RETURN_ON_ERROR(esp_netif_dhcps_start(ap_netif_), kLogTag, "DHCP start failed");
    wifi_config_t config = {};
    std::snprintf(reinterpret_cast<char*>(config.ap.ssid), sizeof(config.ap.ssid), "FingerGate-%02X%02X", mac[4], mac[5]);
    std::strcpy(reinterpret_cast<char*>(config.ap.password), kApPassword);
    config.ap.ssid_len = std::strlen(reinterpret_cast<char*>(config.ap.ssid));
    config.ap.max_connection = 4;
    config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_APSTA), kLogTag, "AP mode failed");
    ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_AP, &config), kLogTag, "AP config failed");
    access_point_active_ = true;
    state_.ap_ready();
    notify_indicator(ProvisioningIndication::AccessPoint);
    ESP_RETURN_ON_ERROR(esp_wifi_start(), kLogTag, "Wi-Fi start failed");
    return start_http_server();
}

esp_err_t Provisioning::start_http_server()
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    ESP_RETURN_ON_ERROR(httpd_start(&server_, &config), kLogTag, "HTTP start failed");
    const httpd_uri_t page = {.uri = "/", .method = HTTP_GET, .handler = setup_page_handler, .user_ctx = this};
    return httpd_register_uri_handler(server_, &page);
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
    return state_.json();
}

esp_err_t Provisioning::configure_wifi(const WifiCredentials& credentials)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!access_point_active_ || connecting_ || state_.is_connected()) return ESP_ERR_INVALID_STATE;
    if (credentials.ssid.empty() || credentials.ssid.size() > 32 || credentials.password.size() > 63 ||
        credentials.ssid.find('\0') != std::string::npos || credentials.password.find('\0') != std::string::npos) return ESP_ERR_INVALID_ARG;
    wifi_config_t config = station_config(credentials);
    ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_STA, &config), kLogTag, "station config failed");
    pending_credentials_ = credentials;
    pending_save_ = true;
    connecting_ = true;
    station_configured_ = true;
    attempt_deadline_ = now_ms() + kAttemptTimeoutMs;
    state_.connecting();
    notify_indicator(ProvisioningIndication::Connecting);
    const esp_err_t result = esp_wifi_connect();
    if (result != ESP_OK) {
        connecting_ = false;
        pending_save_ = false;
        state_.failed("Unable to start Wi-Fi connection");
        notify_indicator(ProvisioningIndication::Failed);
    }
    return result;
}

esp_err_t Provisioning::acknowledge(bool schedule_shutdown)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!access_point_active_ || !state_.is_connected()) return ESP_ERR_INVALID_STATE;
    if (schedule_shutdown) shutdown_deadline_ = now_ms() + kAcknowledgementDelayMs;
    return ESP_OK;
}

void Provisioning::poll()
{
    httpd_handle_t stopped = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const uint64_t now = now_ms();
        if (connecting_ && now >= attempt_deadline_) {
            connecting_ = false;
            pending_save_ = false;
            esp_wifi_disconnect();
            state_.failed("Connection timed out. Check Wi-Fi name and password.");
            notify_indicator(ProvisioningIndication::Failed);
            if (!access_point_active_) reconnect_at_ = now + kReconnectDelayMs;
        }
        if (!access_point_active_ && station_configured_ && !connecting_ && !state_.is_connected() && now >= reconnect_at_) {
            connecting_ = true;
            attempt_deadline_ = now + kAttemptTimeoutMs;
            esp_wifi_connect();
        }
        if (access_point_active_ && shutdown_deadline_ && now >= shutdown_deadline_) {
            shutdown_deadline_ = 0;
            if (state_.is_connected() && esp_wifi_set_mode(WIFI_MODE_STA) == ESP_OK) {
                access_point_active_ = false;
                stopped = server_;
                server_ = nullptr;
                state_.set_network_details("", hostname_);
                notify_indicator(ProvisioningIndication::Idle);
                ESP_LOGI(kLogTag, "AP stopped; STA remains connected");
            }
        }
    }
    // Остановка HTTP не удерживает блокировку, нужную обработчикам событий.
    if (stopped) httpd_stop(stopped);
}

void Provisioning::notify_indicator(ProvisioningIndication indication)
{
    fingerprint_task_.set_provisioning({indication, access_point_active_});
}

void Provisioning::event_handler(void* context, esp_event_base_t base, int32_t id, void* data)
{
    static_cast<Provisioning*>(context)->on_event(base, id, data);
}

void Provisioning::on_event(esp_event_base_t base, int32_t id, void* data)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        connecting_ = false;
        pending_save_ = false;
        pending_credentials_ = {};
        shutdown_deadline_ = 0;
        reconnect_at_ = now_ms() + kReconnectDelayMs;
        state_.failed("Connection failed. Check Wi-Fi name and password.");
        notify_indicator(ProvisioningIndication::Failed);
    }
    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        connecting_ = false;
        if (pending_save_ && ConfigStore(storage_).save_wifi(pending_credentials_) != StoreResult::Ok) {
            state_.failed("Unable to save Wi-Fi credentials; setup is incomplete");
            notify_indicator(ProvisioningIndication::Failed);
            pending_save_ = false;
            pending_credentials_ = {};
            esp_wifi_disconnect();
            return;
        }
        pending_save_ = false;
        pending_credentials_ = {};
        const auto* event = static_cast<const ip_event_got_ip_t*>(data);
        char ip[16] = {};
        esp_ip4addr_ntoa(&event->ip_info.ip, ip, sizeof(ip));
        state_.connected(ip);
        if (!access_point_active_) state_.set_network_details("", hostname_);
        notify_indicator(ProvisioningIndication::Connected);
        if (access_point_active_) shutdown_deadline_ = now_ms() + kShutdownDelayMs;
        ESP_LOGI(kLogTag, "Station connected: %s", ip);
    }
}

}
