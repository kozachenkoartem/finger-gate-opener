#pragma once

#include "auth.hpp"
#include "esp_http_server.h"
#include "provisioning.hpp"
#include "tls_identity.hpp"

namespace fg {
class AdminServer {
public:
    AdminServer(KeyValueStore& storage, Provisioning& provisioning, FingerprintTask& fingerprints)
        : storage_(storage), provisioning_(provisioning), fingerprints_(fingerprints), auth_(storage) {}
    void start();

private:
    static void task_entry(void* context);
    static esp_err_t handler(httpd_req_t* request);
    esp_err_t handle(httpd_req_t* request);
    esp_err_t initialize();
    KeyValueStore& storage_;
    Provisioning& provisioning_;
    FingerprintTask& fingerprints_;
    AuthService auth_;
    TlsIdentity identity_;
    httpd_handle_t server_ = nullptr;
};
}
