#pragma once

#include "auth.hpp"
#include "audit_events.hpp"
#include "esp_http_server.h"
#include "provisioning.hpp"
#include "tls_identity.hpp"
#include "hub_auth.hpp"

namespace fg {
class AdminServer {
public:
    AdminServer(KeyValueStore& storage, Provisioning& provisioning, FingerprintTask& fingerprints, AuditPublisher& audit,
                HubAuth& hub_auth, HubCommandLedger& hub_ledger)
        : storage_(storage), provisioning_(provisioning), fingerprints_(fingerprints), audit_(audit), hub_auth_(hub_auth), hub_ledger_(hub_ledger), auth_(storage) {}
    void start();

private:
    class SseSession;
    static void task_entry(void* context);
    static esp_err_t handler(httpd_req_t* request);
    esp_err_t handle(httpd_req_t* request);
    esp_err_t initialize();
    esp_err_t handle_stream(httpd_req_t* request);
    void close_stream();
    void publish(AuditType type, AuditResultCode result, AuditSource source = AuditSource::Admin);
    KeyValueStore& storage_;
    Provisioning& provisioning_;
    FingerprintTask& fingerprints_;
    AuditPublisher& audit_;
    HubAuth& hub_auth_;
    HubCommandLedger& hub_ledger_;
    AuthService auth_;
    TlsIdentity identity_;
    httpd_handle_t server_ = nullptr;
    SseSession* stream_ = nullptr;
};
}
