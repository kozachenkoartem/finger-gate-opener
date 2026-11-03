#include "http_server.hpp"
#include "api_router.hpp"

#include <cstring>
#include <map>
#include <string>
#include "esp_check.h"
#include "esp_https_server.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/task.h"
#include "mdns.h"

namespace fg {
namespace {
constexpr char kLogTag[] = "admin_https";
constexpr size_t kMaxHeader = 1024;
constexpr uint32_t kServerStartupStack = 12288;
extern const unsigned char kPageStart[] asm("_binary_index_html_start");
extern const unsigned char kPageEnd[] asm("_binary_index_html_end");

uint64_t now_ms() { return esp_timer_get_time() / 1000; }

std::string header(httpd_req_t* request, const char* name)
{
    const size_t size = httpd_req_get_hdr_value_len(request, name);
    if (!size || size > kMaxHeader) return {};
    std::string value(size + 1, '\0');
    if (httpd_req_get_hdr_value_str(request, name, value.data(), value.size()) != ESP_OK) return {};
    value.resize(size);
    return value;
}

esp_err_t json_response(httpd_req_t* request, const char* status, const std::string& body)
{
    httpd_resp_set_status(request, status);
    httpd_resp_set_type(request, "application/json");
    return httpd_resp_send(request, body.data(), body.size());
}

esp_err_t auth_response(httpd_req_t* request, AuthResult result)
{
    switch (result) {
    case AuthResult::Ok: return json_response(request, "200 OK", "{\"ok\":true}");
    case AuthResult::Unauthorized: return json_response(request, "401 Unauthorized", "{\"error\":\"Authentication required or invalid credentials\"}");
    case AuthResult::Forbidden: return json_response(request, "403 Forbidden", "{\"error\":\"Invalid CSRF token\"}");
    case AuthResult::PasswordChangeRequired: return json_response(request, "403 Forbidden", "{\"error\":\"Password change required\"}");
    case AuthResult::RateLimited:
        httpd_resp_set_hdr(request, "Retry-After", "60");
        return json_response(request, "429 Too Many Requests", "{\"error\":\"Too many attempts or active sessions. Try later.\"}");
    case AuthResult::InvalidInput: return json_response(request, "400 Bad Request", "{\"error\":\"Invalid input; new password must be 12 to 128 bytes\"}");
    case AuthResult::Unavailable: return json_response(request, "503 Service Unavailable", "{\"error\":\"Secure storage or cryptography unavailable\"}");
    }
    return ESP_FAIL;
}

void clear_cookie(httpd_req_t* request)
{
    httpd_resp_set_hdr(request, "Set-Cookie", "__Host-fg_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0");
}

std::string session_json(const Session& session)
{
    return "{\"csrf\":\"" + session.csrf + "\",\"password_change_required\":" +
        (session.password_change_required ? "true}" : "false}");
}
}

void AdminServer::start()
{
    if (xTaskCreate(task_entry, "admin_init", kServerStartupStack, this, 2, nullptr) != pdPASS) {
        ESP_LOGE(kLogTag, "Cannot create HTTPS startup task");
    }
}

void AdminServer::task_entry(void* context)
{
    auto* server = static_cast<AdminServer*>(context);
    if (server->initialize() != ESP_OK) ESP_LOGE(kLogTag, "HTTPS unavailable; fingerprint task remains active");
    vTaskDelete(nullptr);
}

esp_err_t AdminServer::initialize()
{
    if (auth_.initialize() != AuthResult::Ok || !identity_.initialize(storage_, provisioning_.hostname())) return ESP_FAIL;
    httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
    config.httpd.max_uri_handlers = 12;
    config.httpd.max_open_sockets = 3;
    config.httpd.max_resp_headers = 12;
    config.httpd.stack_size = 12288;
    config.tls_handshake_timeout_ms = 5000;
    config.servercert = identity_.certificate().data();
    config.servercert_len = identity_.certificate().size();
    config.prvtkey_pem = identity_.private_key().data();
    config.prvtkey_len = identity_.private_key().size();
    ESP_RETURN_ON_ERROR(httpd_ssl_start(&server_, &config), kLogTag, "TLS server start failed");
    struct Route { const char* uri; httpd_method_t method; };
    for (const Route route : {Route{"/", HTTP_GET}, {"/api/login", HTTP_POST}, {"/api/session", HTTP_GET},
                            {"/api/password", HTTP_POST}, {"/api/logout", HTTP_POST}, {"/api/status", HTTP_GET},
                            {"/api/wifi", HTTP_POST}, {"/api/acknowledge", HTTP_POST}}) {
        const httpd_uri_t uri = {.uri = route.uri, .method = route.method, .handler = handler, .user_ctx = this};
        const esp_err_t result = httpd_register_uri_handler(server_, &uri);
        if (result != ESP_OK) { httpd_ssl_stop(server_); server_ = nullptr; return result; }
    }
    ESP_LOGI(kLogTag, "HTTPS ready: https://%s.local/ (or device IP)", provisioning_.hostname().c_str());
    // Объявляем только реально работающий HTTPS-сервис, один раз на загрузку.
    esp_err_t result = mdns_init();
    if (result == ESP_OK) result = mdns_hostname_set(provisioning_.hostname().c_str());
    if (result == ESP_OK) result = mdns_instance_name_set("Finger Gate");
    if (result == ESP_OK) result = mdns_service_add(nullptr, "_https", "_tcp", 443, nullptr, 0);
    if (result != ESP_OK) ESP_LOGE(kLogTag, "mDNS unavailable: %s; HTTPS still accessible by IP", esp_err_to_name(result));
    return ESP_OK;
}

esp_err_t AdminServer::handler(httpd_req_t* request)
{
    return static_cast<AdminServer*>(request->user_ctx)->handle(request);
}

esp_err_t AdminServer::handle(httpd_req_t* request)
{
    httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    httpd_resp_set_hdr(request, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(request, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(request, "Referrer-Policy", "no-referrer");
    const std::string path = request->uri;
    if (path == "/") {
        httpd_resp_set_type(request, "text/html; charset=utf-8");
        httpd_resp_set_hdr(request, "Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
        return httpd_resp_send(request, reinterpret_cast<const char*>(kPageStart), kPageEnd - kPageStart);
    }
    const bool mutation = request->method == HTTP_POST;
    if (mutation) {
        const std::string origin = header(request, "Origin");
        if (header(request, "Sec-Fetch-Site") == "cross-site" ||
            (!origin.empty() && origin != "https://" + header(request, "Host"))) {
            return json_response(request, "403 Forbidden", "{\"error\":\"Cross-origin request denied\"}");
        }
    }
    const std::string token = session_cookie_token(header(request, "Cookie"));
    const std::string csrf = header(request, "X-CSRF-Token");
    Session session;
    if (path != "/api/login") {
        const bool allow_change = path == "/api/session" || path == "/api/password" || path == "/api/logout";
        const AuthResult access = auth_.authorize(token, csrf, mutation, allow_change, now_ms(), &session);
        if (access != AuthResult::Ok) return auth_response(request, access);
    }
    std::map<std::string, std::string> fields;
    if (mutation) {
        if (request->content_len <= 0 || request->content_len > kMaxAdminBody) {
            httpd_resp_set_hdr(request, "Connection", "close");
            json_response(request, "413 Payload Too Large", "{\"error\":\"Request body must be 1 to 1024 bytes\"}");
            return ESP_FAIL;
        }
        std::string body(request->content_len, '\0');
        size_t received = 0;
        while (received < body.size()) {
            const int count = httpd_req_recv(request, body.data() + received, body.size() - received);
            if (count <= 0) return ESP_FAIL;
            received += count;
        }
        std::vector<std::string> allowed;
        if (path == "/api/login") allowed = {"username", "password"};
        if (path == "/api/password") allowed = {"new_password"};
        if (path == "/api/wifi") allowed = {"ssid", "password"};
        if (!parse_admin_json(header(request, "Content-Type"), body, allowed, &fields)) {
            return json_response(request, "400 Bad Request", "{\"error\":\"Expected a JSON object with known string fields\"}");
        }
    }
    if (path == "/api/login") {
        const AuthResult result = auth_.login(fields["username"], fields["password"], now_ms(), &session);
        ESP_LOGI(kLogTag, "Audit: login result %d", static_cast<int>(result));
        if (result != AuthResult::Ok) return auth_response(request, result);
        const std::string cookie = std::string(kSessionCookie) + "=" + session.token + "; Path=/; Secure; HttpOnly; SameSite=Strict";
        httpd_resp_set_hdr(request, "Set-Cookie", cookie.c_str());
        return json_response(request, "200 OK", session_json(session));
    }
    if (path == "/api/session") return json_response(request, "200 OK", session_json(session));
    if (path == "/api/status") return json_response(request, "200 OK", provisioning_.status_json());
    if (path == "/api/password") {
        const AuthResult result = auth_.change_password(token, csrf, fields["new_password"], now_ms());
        ESP_LOGI(kLogTag, "Audit: password replacement result %d", static_cast<int>(result));
        if (result == AuthResult::Ok) clear_cookie(request);
        return auth_response(request, result);
    }
    if (path == "/api/logout") {
        const AuthResult result = auth_.logout(token, csrf, now_ms());
        if (result == AuthResult::Ok) clear_cookie(request);
        return auth_response(request, result);
    }
    if (path == "/api/wifi") {
        const esp_err_t result = provisioning_.configure_wifi({fields["ssid"], fields["password"]});
        ESP_LOGI(kLogTag, "Audit: Wi-Fi setup result %d", result);
        return result == ESP_OK ? json_response(request, "202 Accepted", "{\"ok\":true}") :
            json_response(request, "400 Bad Request", "{\"error\":\"Wi-Fi setup requires an idle provisioning AP and valid credentials\"}");
    }
    if (path == "/api/acknowledge") {
        if (provisioning_.acknowledge(false) != ESP_OK) return json_response(request, "400 Bad Request", "{\"error\":\"Provisioning is not ready for acknowledgement\"}");
        const esp_err_t sent = json_response(request, "200 OK", "{\"ok\":true}");
        if (sent == ESP_OK) provisioning_.acknowledge();
        return sent;
    }
    return json_response(request, "404 Not Found", "{\"error\":\"Unknown endpoint\"}");
}
}
