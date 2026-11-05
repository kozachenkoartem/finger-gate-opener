#include "http_server.hpp"
#include "api_router.hpp"

#include <algorithm>
#include <cstring>
#include <atomic>
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

std::string audit_event_json(const AuditRecord& event)
{
    const std::string name(event.name.data(), std::find(event.name.begin(), event.name.end(), '\0'));
    const std::string request_id(event.request_id.data(), std::find(event.request_id.begin(), event.request_id.end(), '\0'));
    return "{\"id\":" + json_quote(std::to_string(event.id.epoch) + ":" + std::to_string(event.id.sequence)) +
        ",\"type\":" + std::to_string(static_cast<unsigned>(event.type)) + ",\"result\":" +
        std::to_string(static_cast<unsigned>(event.result)) + ",\"source\":" +
        std::to_string(static_cast<unsigned>(event.source)) + ",\"slot\":" + std::to_string(event.slot) +
        ",\"name\":" + json_quote(name) + ",\"request_id\":" + json_quote(request_id) + "}";
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

class AdminServer::SseSession {
public:
    SseSession(AdminServer& owner, httpd_req_t* request, uint32_t generation)
        : owner_(owner), request_(request), socket_(httpd_req_to_sockfd(request)), generation_(generation), stream_(owner.audit_, 8) {
        stream_.set_ready_callback([this] { schedule(); });
    }

    EventStreamResult start(AuditCursor cursor)
    {
        const EventStreamResult result = stream_.open(cursor, generation_, &replay_);
        if (result == EventStreamResult::Ok) schedule();
        return result;
    }

    bool closed() const { return completed_.load(); }

    void close()
    {
        stream_.close();
        schedule();
    }

private:
    static void worker(void* context)
    {
        auto* session = static_cast<SseSession*>(context);
        session->queued_.store(false);
        if (session->owner_.hub_auth_.generation() != session->generation_ || session->stream_.closed()) {
            session->finish();
            return;
        }
        std::string frame;
        AuditRecord record;
        if (session->replay_index_ < session->replay_.events.size()) frame = AuditEventStream::sse_frame(session->replay_.events[session->replay_index_++]);
        else if (session->stream_.take_next(session->generation_, &record)) frame = AuditEventStream::sse_frame(record);
        else return;
        if (httpd_resp_send_chunk(session->request_, frame.data(), frame.size()) != ESP_OK) {
            session->stream_.close();
            session->finish();
            return;
        }
        session->schedule();
    }

    void schedule()
    {
        bool expected = false;
        if (!queued_.compare_exchange_strong(expected, true)) return;
        if (httpd_queue_work(owner_.server_, worker, this) != ESP_OK) {
            queued_.store(false);
            stream_.close();
            finish();
        }
    }

    void finish()
    {
        if (completed_.exchange(true)) return;
        stream_.close();
        httpd_resp_send_chunk(request_, nullptr, 0);
        httpd_req_async_handler_complete(request_);
        httpd_sess_trigger_close(owner_.server_, socket_);
    }

    AdminServer& owner_;
    httpd_req_t* request_;
    int socket_;
    uint32_t generation_;
    AuditEventStream stream_;
    AuditPage replay_;
    size_t replay_index_ = 0;
    std::atomic<bool> queued_{false};
    std::atomic<bool> completed_{false};
};

void AdminServer::publish(AuditType type, AuditResultCode result, AuditSource source)
{
    AuditRecord event;
    event.type = type;
    event.result = result;
    event.source = source;
    event.elapsed_ms = now_ms();
    audit_.publish(event);
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
    config.httpd.max_uri_handlers = 25;
    config.httpd.max_open_sockets = 4;
    config.httpd.send_wait_timeout = 1;
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
                            {"/api/wifi", HTTP_POST}, {"/api/acknowledge", HTTP_POST},
                            {"/api/fingerprints", HTTP_GET}, {"/api/enrollment/start", HTTP_POST},
                            {"/api/enrollment/cancel", HTTP_POST}, {"/api/users/rename", HTTP_POST},
                            {"/api/users/role", HTTP_POST}, {"/api/users/delete", HTTP_POST},
                             {"/api/network/recovery", HTTP_POST}, {"/api/network/ap-password", HTTP_POST}}) {
        const httpd_uri_t uri = {.uri = route.uri, .method = route.method, .handler = handler, .user_ctx = this};
        const esp_err_t result = httpd_register_uri_handler(server_, &uri);
        if (result != ESP_OK) { httpd_ssl_stop(server_); server_ = nullptr; return result; }
    }
    for (const Route route : {Route{"/api/hub/token", HTTP_POST}, Route{"/api/hub/token", HTTP_DELETE},
                              Route{"/api/audit", HTTP_GET}, Route{"/api/audit/clear", HTTP_POST},
                              Route{"/api/v1/status", HTTP_GET}, Route{"/api/v1/events", HTTP_GET}, Route{"/api/v1/events/stream", HTTP_GET},
                              Route{"/api/v1/gate/open", HTTP_POST}}) {
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

void AdminServer::close_stream()
{
    if (stream_) stream_->close();
}

esp_err_t AdminServer::handle_stream(httpd_req_t* request)
{
    AuditCursor cursor;
    if (!parse_event_cursor(header(request, "Last-Event-ID"), &cursor))
        return json_response(request, "400 Bad Request", "{\"error\":\"Invalid Last-Event-ID\"}");
    if (stream_ && !stream_->closed())
        return json_response(request, "409 Conflict", "{\"error\":\"An event stream is already active\"}");
    delete stream_;
    stream_ = nullptr;
    httpd_req_t* async_request = nullptr;
    if (httpd_req_async_handler_begin(request, &async_request) != ESP_OK)
        return json_response(request, "503 Service Unavailable", "{\"error\":\"Event stream unavailable\"}");
    httpd_resp_set_type(async_request, "text/event-stream");
    httpd_resp_set_hdr(async_request, "Cache-Control", "no-store");
    stream_ = new SseSession(*this, async_request, hub_auth_.generation());
    const EventStreamResult result = stream_->start(cursor);
    if (result == EventStreamResult::Ok) return ESP_OK;
    delete stream_;
    stream_ = nullptr;
    const char* status = result == EventStreamResult::Busy || result == EventStreamResult::Reset ? "409 Conflict" : "503 Service Unavailable";
    json_response(async_request, status, "{\"error\":\"Event cursor requires reset or stream is busy\"}");
    httpd_req_async_handler_complete(async_request);
    return ESP_OK;
}

esp_err_t AdminServer::handle(httpd_req_t* request)
{
    httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    httpd_resp_set_hdr(request, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(request, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(request, "Referrer-Policy", "no-referrer");
    const std::string uri = request->uri;
    const size_t query_start = uri.find('?');
    const std::string path = uri.substr(0, query_start);
    const std::string query = query_start == std::string::npos ? "" : uri.substr(query_start + 1);
    if (path == "/") {
        httpd_resp_set_type(request, "text/html; charset=utf-8");
        httpd_resp_set_hdr(request, "Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
        return httpd_resp_send(request, reinterpret_cast<const char*>(kPageStart), kPageEnd - kPageStart);
    }
    const bool hub_api = path.rfind("/api/v1/", 0) == 0;
    if (hub_api) {
        if (!header(request, "Cookie").empty() || !header(request, "X-CSRF-Token").empty())
            return json_response(request, "400 Bad Request", "{\"error\":\"Hub routes do not accept session credentials\"}");
        const HubAuthResult access = hub_auth_.authorize_bearer(header(request, "Authorization"), now_ms());
        if (access != HubAuthResult::Ok) {
            publish(AuditType::Authentication, AuditResultCode::Rejected, AuditSource::Hub);
            if (access == HubAuthResult::RateLimited) {
                httpd_resp_set_hdr(request, "Retry-After", "60");
                return json_response(request, "429 Too Many Requests", "{\"error\":\"Too many token attempts\"}");
            }
            return json_response(request, access == HubAuthResult::Malformed ? "400 Bad Request" : "401 Unauthorized", "{\"error\":\"Invalid Bearer token\"}");
        }
    }
    if (path == "/api/v1/events/stream") return handle_stream(request);
    const bool mutation = request->method == HTTP_POST || request->method == HTTP_DELETE;
    if (mutation && request->method == HTTP_POST) {
        const std::string origin = header(request, "Origin");
        if (header(request, "Sec-Fetch-Site") == "cross-site" ||
            (!origin.empty() && origin != "https://" + header(request, "Host"))) {
            return json_response(request, "403 Forbidden", "{\"error\":\"Cross-origin request denied\"}");
        }
    }
    const std::string token = session_cookie_token(header(request, "Cookie"));
    const std::string csrf = header(request, "X-CSRF-Token");
    Session session;
    if (!hub_api && path != "/api/login") {
        const bool allow_change = path == "/api/session" || path == "/api/password" || path == "/api/logout";
        const AuthResult access = auth_.authorize(token, csrf, mutation, allow_change, now_ms(), &session);
        if (access != AuthResult::Ok) {
            publish(AuditType::Authentication, AuditResultCode::Rejected);
            return auth_response(request, access);
        }
    }
    std::map<std::string, std::string> fields;
    if (mutation && request->method == HTTP_POST) {
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
        if (path == "/api/v1/gate/open") allowed = {"request_id"};
        if (path == "/api/password") allowed = {"new_password"};
        if (path == "/api/wifi") allowed = {"ssid", "password"};
        if (path == "/api/network/ap-password") allowed = {"password"};
        if (path == "/api/enrollment/start") allowed = {"name"};
        if (path == "/api/enrollment/cancel") allowed = {"operation_id"};
        if (path == "/api/users/rename") allowed = {"slot", "name"};
        if (path == "/api/users/role") allowed = {"slot", "role"};
        if (path == "/api/users/delete") allowed = {"slot"};
        if (!parse_admin_json(header(request, "Content-Type"), body, allowed, &fields)) {
            return json_response(request, "400 Bad Request", "{\"error\":\"Expected a JSON object with known string fields\"}");
        }
    }
    if (path == "/api/hub/token") {
        if (request->method == HTTP_DELETE) {
            const HubAuthResult result = hub_auth_.revoke();
            if (result == HubAuthResult::Ok) close_stream();
            publish(AuditType::Authentication, result == HubAuthResult::Ok ? AuditResultCode::Accepted : AuditResultCode::Failed);
            return json_response(request, result == HubAuthResult::Ok ? "200 OK" : "503 Service Unavailable", "{\"ok\":true}");
        }
        std::string token;
        const HubAuthResult result = hub_auth_.create_or_rotate(&token);
        if (result == HubAuthResult::Ok) close_stream();
        publish(AuditType::Authentication, result == HubAuthResult::Ok ? AuditResultCode::Accepted : AuditResultCode::Failed);
        return result == HubAuthResult::Ok ? json_response(request, "200 OK", "{\"token\":" + json_quote(token) + ",\"api_version\":1}") :
            json_response(request, "503 Service Unavailable", "{\"error\":\"Hub token storage unavailable\"}");
    }
    if (path == "/api/audit") {
        AuditPage page;
        if (audit_.store().read_after({}, AuditStore::kRecordCapacity, &page) != AuditResult::Ok)
            return json_response(request, "503 Service Unavailable", "{\"error\":\"Audit storage unavailable\"}");
        std::string body = "{\"events\":[";
        for (size_t index = 0; index < page.events.size(); ++index) {
            if (index) body += ',';
            const AuditRecord& event = page.events[index];
            body += "{\"id\":" + json_quote(std::to_string(event.id.epoch) + ":" + std::to_string(event.id.sequence)) +
                    ",\"type\":" + std::to_string(static_cast<unsigned>(event.type)) + ",\"result\":" +
                    std::to_string(static_cast<unsigned>(event.result)) + ",\"slot\":" + std::to_string(event.slot) + "}";
        }
        return json_response(request, "200 OK", body + "]}");
    }
    if (path == "/api/audit/clear") {
        const AuditResult result = audit_.store().clear();
        publish(AuditType::System, result == AuditResult::Ok ? AuditResultCode::Cleared : AuditResultCode::Failed);
        return json_response(request, result == AuditResult::Ok ? "200 OK" : "503 Service Unavailable", "{\"ok\":true}");
    }
    if (path == "/api/v1/status")
        return json_response(request, "200 OK", "{\"api_version\":1,\"schema_version\":1,\"device\":" + provisioning_.status_json() + "}");
    if (path == "/api/v1/events") {
        EventQuery event_query;
        if (!parse_event_query(query, &event_query))
            return json_response(request, "400 Bad Request", "{\"error\":\"Invalid events query\"}");
        AuditPage page;
        const AuditResult result = audit_.store().read_after(event_query.after, event_query.limit, &page);
        AuditPage retained;
        const AuditResult retained_result = audit_.store().read_after({}, AuditStore::kRecordCapacity, &retained);
        if (result == AuditResult::Invalid && retained_result == AuditResult::Ok) {
            const std::string first = retained.events.empty() ? "0:0" :
                std::to_string(retained.events.front().id.epoch) + ":" + std::to_string(retained.events.front().id.sequence);
            const std::string last = retained.events.empty() ? "0:0" :
                std::to_string(retained.events.back().id.epoch) + ":" + std::to_string(retained.events.back().id.sequence);
            return json_response(request, "409 Conflict", "{\"error\":\"Event cursor requires reset\",\"retained_from\":" +
                json_quote(first) + ",\"retained_to\":" + json_quote(last) + "}");
        }
        if (result != AuditResult::Ok) return json_response(request, "503 Service Unavailable", "{\"error\":\"Audit storage unavailable\"}");
        if (retained_result != AuditResult::Ok) return json_response(request, "503 Service Unavailable", "{\"error\":\"Audit storage unavailable\"}");
        std::string body = "{\"api_version\":1,\"events\":[";
        bool comma = false;
        for (const auto& event : page.events) {
            if (comma) body += ',';
            comma = true;
            body += audit_event_json(event);
        }
        const std::string first = retained.events.empty() ? "0:0" :
            std::to_string(retained.events.front().id.epoch) + ":" + std::to_string(retained.events.front().id.sequence);
        const std::string last = retained.events.empty() ? "0:0" :
            std::to_string(retained.events.back().id.epoch) + ":" + std::to_string(retained.events.back().id.sequence);
        return json_response(request, "200 OK", body + "],\"next_after\":" +
            json_quote(std::to_string(page.next_after.epoch) + ":" + std::to_string(page.next_after.sequence)) +
            ",\"has_more\":" + (page.has_more ? "true" : "false") + ",\"retained_from\":" +
            json_quote(first) + ",\"retained_to\":" + json_quote(last) + "}");
    }
    if (path == "/api/v1/gate/open") {
        const std::string& request_id = fields["request_id"];
        const HubLedgerResult reserved = hub_ledger_.reserve(request_id);
        if (reserved == HubLedgerResult::Duplicate) {
            HubCommand command;
            hub_ledger_.get(request_id, &command);
            return json_response(request, "202 Accepted", "{\"request_id\":" + json_quote(request_id) + ",\"state\":" + std::to_string(static_cast<unsigned>(command.state)) + "}");
        }
        if (reserved != HubLedgerResult::Ok) return json_response(request, reserved == HubLedgerResult::Invalid ? "400 Bad Request" : "503 Service Unavailable", "{\"error\":\"Command unavailable\"}");
        AuditRecord event;
        event.type = AuditType::Gate;
        event.result = AuditResultCode::Accepted;
        event.source = AuditSource::Hub;
        event.elapsed_ms = now_ms();
        std::memcpy(event.request_id.data(), request_id.data(), std::min(request_id.size(), event.request_id.size()));
        if (!audit_.append(event) || hub_ledger_.mark_executable(request_id) != HubLedgerResult::Ok) {
            hub_ledger_.complete(request_id, HubCommandState::Failed);
            return json_response(request, "503 Service Unavailable", "{\"error\":\"Command was not accepted\"}");
        }
        FingerprintCommand command{FingerprintCommandType::HubOpen, 0, {}, Role::User, 0, AuditSource::Hub, request_id};
        if (!fingerprints_.submit(command).id) {
            hub_ledger_.complete(request_id, HubCommandState::Failed);
            return json_response(request, "503 Service Unavailable", "{\"error\":\"Gate queue unavailable\"}");
        }
        return json_response(request, "202 Accepted", "{\"request_id\":" + json_quote(request_id) + ",\"state\":\"accepted\"}");
    }
    if (path == "/api/login") {
        const AuthResult result = auth_.login(fields["username"], fields["password"], now_ms(), &session);
        ESP_LOGI(kLogTag, "Audit: login result %d", static_cast<int>(result));
        publish(AuditType::Authentication, result == AuthResult::Ok ? AuditResultCode::Granted : AuditResultCode::Rejected);
        if (result != AuthResult::Ok) return auth_response(request, result);
        const std::string cookie = std::string(kSessionCookie) + "=" + session.token + "; Path=/; Secure; HttpOnly; SameSite=Strict";
        httpd_resp_set_hdr(request, "Set-Cookie", cookie.c_str());
        return json_response(request, "200 OK", session_json(session));
    }
    if (path == "/api/session") return json_response(request, "200 OK", session_json(session));
    if (path == "/api/status") return json_response(request, "200 OK", provisioning_.status_json());
    if (path == "/api/fingerprints") return json_response(request, "200 OK", fingerprints_.snapshot_json());
    if (path == "/api/enrollment/start" || path == "/api/enrollment/cancel" ||
        path == "/api/users/rename" || path == "/api/users/role" || path == "/api/users/delete") {
        FingerprintCommand command{};
        uint32_t parsed = 0;
        if (path == "/api/enrollment/start") {
            command.type = FingerprintCommandType::Enroll;
            command.name = fields["name"];
            if (command.name.size() > 64) return json_response(request, "400 Bad Request", "{\"error\":\"Name exceeds 64 bytes\"}");
        } else if (path == "/api/enrollment/cancel") {
            command.type = FingerprintCommandType::Cancel;
            if (!parse_unsigned(fields["operation_id"], UINT32_MAX, &parsed) || !parsed)
                return json_response(request, "400 Bad Request", "{\"error\":\"Invalid enrollment operation ID\"}");
            command.operation_id = parsed;
        } else {
            if (!parse_unsigned(fields["slot"], UserRegistry::kSlotCount - 1, &parsed))
                return json_response(request, "400 Bad Request", "{\"error\":\"Invalid slot\"}");
            command.slot = parsed;
            if (path == "/api/users/rename") {
                command.type = FingerprintCommandType::Rename;
                command.name = fields["name"];
                if (command.name.empty() || command.name.size() > 64)
                    return json_response(request, "400 Bad Request", "{\"error\":\"Name must be 1 to 64 bytes\"}");
            } else if (path == "/api/users/role") {
                command.type = FingerprintCommandType::SetRole;
                if (fields["role"] != "User" && fields["role"] != "Master")
                    return json_response(request, "400 Bad Request", "{\"error\":\"Role must be User or Master\"}");
                command.role = fields["role"] == "Master" ? Role::Master : Role::User;
            } else command.type = FingerprintCommandType::Delete;
        }
        const CommandReceipt receipt = fingerprints_.submit(command);
        if (!receipt.id) return json_response(request, "503 Service Unavailable", "{\"error\":\"Fingerprint command queue is full or unavailable\"}");
        return json_response(request, "202 Accepted", "{\"command_id\":" + std::to_string(receipt.id) + "}");
    }
    if (path == "/api/password") {
        const AuthResult result = auth_.change_password(token, csrf, fields["new_password"], now_ms());
        ESP_LOGI(kLogTag, "Audit: password replacement result %d", static_cast<int>(result));
        publish(AuditType::Authentication, result == AuthResult::Ok ? AuditResultCode::Accepted : AuditResultCode::Failed);
        if (result == AuthResult::Ok) clear_cookie(request);
        return auth_response(request, result);
    }
    if (path == "/api/logout") {
        const AuthResult result = auth_.logout(token, csrf, now_ms());
        publish(AuditType::Authentication, result == AuthResult::Ok ? AuditResultCode::Accepted : AuditResultCode::Failed);
        if (result == AuthResult::Ok) clear_cookie(request);
        return auth_response(request, result);
    }
    if (path == "/api/wifi" || path == "/api/acknowledge" || path == "/api/network/recovery" || path == "/api/network/ap-password") {
        const auto operation = path == "/api/wifi" ? NetworkOperation::Configure :
            path == "/api/acknowledge" ? NetworkOperation::Acknowledge :
            path == "/api/network/recovery" ? NetworkOperation::Recovery : NetworkOperation::ApPassword;
        const WifiCredentials credentials = operation == NetworkOperation::Configure ? WifiCredentials{fields["ssid"], fields["password"]} : WifiCredentials{};
        if ((operation == NetworkOperation::Configure && !valid_wifi_credentials(credentials)) ||
            (operation == NetworkOperation::ApPassword && !valid_ap_password(fields["password"]))) {
            publish(AuditType::Network, AuditResultCode::Failed);
            return json_response(request, "400 Bad Request", "{\"error\":\"Invalid Wi-Fi settings; AP password must be 8 to 63 printable ASCII bytes\"}");
        }
        const uint32_t id = provisioning_.reserve(operation, credentials,
            operation == NetworkOperation::ApPassword ? fields["password"] : "");
        if (!id) {
            publish(AuditType::Network, AuditResultCode::Failed);
            return json_response(request, "503 Service Unavailable", "{\"error\":\"Network operation busy or unavailable in current state\"}");
        }
        publish(AuditType::Network, AuditResultCode::Accepted);
        const esp_err_t sent = json_response(request, "202 Accepted", "{\"command_id\":" + std::to_string(id) + "}");
        provisioning_.finish_response(id, sent == ESP_OK);
        return sent;
    }
    return json_response(request, "404 Not Found", "{\"error\":\"Unknown endpoint\"}");
}
}
