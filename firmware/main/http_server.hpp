#pragma once

#include "auth.hpp"
#include "audit_events.hpp"
#include "esp_http_server.h"
#include "provisioning.hpp"
#include "tls_identity.hpp"

namespace fg {
class AdminServer {
public:
    AdminServer(KeyValueStore& storage, Provisioning& provisioning, FingerprintTask& fingerprints, AuditPublisher& audit)
        : storage_(storage), provisioning_(provisioning), fingerprints_(fingerprints), audit_(audit), auth_(storage) {}
    void start();

private:
    static void task_entry(void* context);
    static esp_err_t handler(httpd_req_t* request);
    esp_err_t handle(httpd_req_t* request);
    esp_err_t initialize();
    void publish(AuditType type, AuditResultCode result);
    KeyValueStore& storage_;
    Provisioning& provisioning_;
    FingerprintTask& fingerprints_;
    AuditPublisher& audit_;
    AuthService auth_;
    TlsIdentity identity_;
    httpd_handle_t server_ = nullptr;
};
}
