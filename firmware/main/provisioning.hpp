#pragma once

#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_netif.h"

namespace fg {

class Provisioning {
public:
    esp_err_t start();

private:
    static void event_handler(void* context, esp_event_base_t event_base, int32_t event_id, void* event_data);
    static esp_err_t setup_page_handler(httpd_req_t* request);
    static esp_err_t configure_wifi_handler(httpd_req_t* request);

    esp_err_t start_http_server();
    esp_err_t configure_station(const char* body, size_t size);
    void on_event(esp_event_base_t event_base, int32_t event_id);

    esp_netif_t* ap_netif_ = nullptr;
    esp_netif_t* station_netif_ = nullptr;
    httpd_handle_t server_ = nullptr;
};

}
