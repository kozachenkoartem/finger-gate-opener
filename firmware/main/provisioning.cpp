#include "provisioning.hpp"

#include <cstring>
#include <cstdio>
#include <string>
#include <vector>

#include "esp_check.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "lwip/ip4_addr.h"

namespace fg {
namespace {
constexpr char kLogTag[] = "provisioning";
constexpr char kApPassword[] = "fingergate";
constexpr char kSetupPage[] =
    "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>Finger Gate Setup</title><h1>Finger Gate</h1>"
    "<form method=post action=/api/wifi><label>Wi-Fi name <input name=ssid required></label><br>"
    "<label>Password <input name=password type=password></label><br><button>Connect</button></form>";

std::string form_value(const std::string& body, const char* name)
{
    const std::string prefix = std::string(name) + "=";
    const size_t start = body.find(prefix);
    if (start == std::string::npos) return {};
    const size_t value_start = start + prefix.size();
    const size_t end = body.find('&', value_start);
    return body.substr(value_start, end - value_start);
}
}

esp_err_t Provisioning::start()
{
    ESP_RETURN_ON_ERROR(esp_netif_init(), kLogTag, "network interface initialization failed");
    ESP_RETURN_ON_ERROR(esp_event_loop_create_default(), kLogTag, "event loop initialization failed");
    ap_netif_ = esp_netif_create_default_wifi_ap();
    station_netif_ = esp_netif_create_default_wifi_sta();
    if (ap_netif_ == nullptr || station_netif_ == nullptr) return ESP_ERR_NO_MEM;
    ESP_RETURN_ON_ERROR(esp_netif_dhcps_stop(ap_netif_), kLogTag, "AP DHCP stop failed");
    esp_netif_ip_info_t ap_ip = {};
    IP4_ADDR(&ap_ip.ip, 192, 168, 1, 1);
    IP4_ADDR(&ap_ip.gw, 192, 168, 1, 1);
    IP4_ADDR(&ap_ip.netmask, 255, 255, 255, 0);
    ESP_RETURN_ON_ERROR(esp_netif_set_ip_info(ap_netif_, &ap_ip), kLogTag, "AP IP setup failed");
    ESP_RETURN_ON_ERROR(esp_netif_dhcps_start(ap_netif_), kLogTag, "AP DHCP start failed");

    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_RETURN_ON_ERROR(esp_wifi_init(&init), kLogTag, "Wi-Fi initialization failed");
    ESP_RETURN_ON_ERROR(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, event_handler, this, nullptr),
                        kLogTag, "Wi-Fi event registration failed");
    ESP_RETURN_ON_ERROR(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, event_handler, this, nullptr),
                        kLogTag, "IP event registration failed");

    uint8_t mac[6] = {};
    ESP_RETURN_ON_ERROR(esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP), kLogTag, "AP MAC read failed");
    wifi_config_t ap_config = {};
    std::snprintf(reinterpret_cast<char*>(ap_config.ap.ssid), sizeof(ap_config.ap.ssid), "FingerGate-%02X%02X", mac[4], mac[5]);
    std::strncpy(reinterpret_cast<char*>(ap_config.ap.password), kApPassword, sizeof(ap_config.ap.password) - 1);
    ap_config.ap.ssid_len = std::strlen(reinterpret_cast<char*>(ap_config.ap.ssid));
    ap_config.ap.max_connection = 4;
    ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_APSTA), kLogTag, "Wi-Fi mode setup failed");
    ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_AP, &ap_config), kLogTag, "AP configuration failed");
    ESP_RETURN_ON_ERROR(esp_wifi_start(), kLogTag, "Wi-Fi start failed");
    return start_http_server();
}

esp_err_t Provisioning::start_http_server()
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    ESP_RETURN_ON_ERROR(httpd_start(&server_, &config), kLogTag, "HTTP server start failed");
    const httpd_uri_t setup_page = {.uri = "/", .method = HTTP_GET, .handler = setup_page_handler, .user_ctx = this};
    const httpd_uri_t configure_wifi = {.uri = "/api/wifi", .method = HTTP_POST, .handler = configure_wifi_handler, .user_ctx = this};
    ESP_RETURN_ON_ERROR(httpd_register_uri_handler(server_, &setup_page), kLogTag, "setup page registration failed");
    return httpd_register_uri_handler(server_, &configure_wifi);
}

esp_err_t Provisioning::setup_page_handler(httpd_req_t* request)
{
    httpd_resp_set_type(request, "text/html");
    return httpd_resp_sendstr(request, kSetupPage);
}

esp_err_t Provisioning::configure_wifi_handler(httpd_req_t* request)
{
    auto* provisioning = static_cast<Provisioning*>(request->user_ctx);
    if (request->content_len == 0 || request->content_len > 192) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request");
    std::vector<char> body(request->content_len + 1, '\0');
    const int received = httpd_req_recv(request, body.data(), request->content_len);
    if (received != request->content_len) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "incomplete request");
    const esp_err_t result = provisioning->configure_station(body.data(), request->content_len);
    if (result != ESP_OK) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid Wi-Fi settings");
    return httpd_resp_sendstr(request, "Connecting to the selected Wi-Fi network.");
}

esp_err_t Provisioning::configure_station(const char* body, size_t size)
{
    const std::string request(body, size);
    const std::string ssid = form_value(request, "ssid");
    const std::string password = form_value(request, "password");
    if (ssid.empty() || ssid.size() > 32 || password.size() > 63) return ESP_ERR_INVALID_ARG;
    wifi_config_t config = {};
    std::memcpy(config.sta.ssid, ssid.data(), ssid.size());
    std::memcpy(config.sta.password, password.data(), password.size());
    ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_STA, &config), kLogTag, "station configuration failed");
    return esp_wifi_connect();
}

void Provisioning::event_handler(void* context, esp_event_base_t event_base, int32_t event_id, void*)
{
    static_cast<Provisioning*>(context)->on_event(event_base, event_id);
}

void Provisioning::on_event(esp_event_base_t event_base, int32_t event_id)
{
    if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ESP_LOGI(kLogTag, "Station connected; provisioning AP remains available for this test");
    }
}

}
