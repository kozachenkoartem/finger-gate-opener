#include "api_router.hpp"

#include <algorithm>
#include <memory>
#include "cJSON.h"

namespace fg {
std::string json_quote(const std::string& value)
{
    constexpr char kHex[] = "0123456789abcdef";
    std::string result = "\"";
    for (const unsigned char c : value) {
        if (c == '"' || c == '\\') { result += '\\'; result += static_cast<char>(c); }
        else if (c < 0x20) {
            result += "\\u00";
            result += kHex[c >> 4];
            result += kHex[c & 15];
        } else result += static_cast<char>(c);
    }
    return result + "\"";
}

bool parse_unsigned(const std::string& value, uint32_t maximum, uint32_t* output)
{
    if (value.empty()) return false;
    uint32_t number = 0;
    for (const char c : value) {
        if (c < '0' || c > '9') return false;
        const uint32_t digit = c - '0';
        if (digit > maximum || number > (maximum - digit) / 10) return false;
        number = number * 10 + digit;
    }
    *output = number;
    return true;
}

bool parse_event_cursor(const std::string& text, AuditCursor* cursor)
{
    if (text.empty()) { *cursor = {}; return true; }
    const size_t colon = text.find(':');
    if (colon == 0 || colon == std::string::npos || colon + 1 == text.size() || text.find(':', colon + 1) != std::string::npos) return false;
    uint64_t values[2]{};
    size_t part = 0;
    for (const char character : text) {
        if (character == ':') { ++part; continue; }
        if (character < '0' || character > '9' || values[part] > (UINT64_MAX - static_cast<uint64_t>(character - '0')) / 10) return false;
        values[part] = values[part] * 10 + static_cast<uint64_t>(character - '0');
    }
    if (values[0] > UINT32_MAX) return false;
    *cursor = {static_cast<uint32_t>(values[0]), values[1]};
    return true;
}
bool parse_event_query(const std::string& query, EventQuery* output)
{
    if (!output) return false;
    EventQuery parsed;
    if (query.empty()) { *output = parsed; return true; }
    bool seen_after = false;
    bool seen_limit = false;
    size_t start = 0;
    while (start < query.size()) {
        const size_t end = query.find('&', start);
        const std::string field = query.substr(start, end == std::string::npos ? std::string::npos : end - start);
        const size_t separator = field.find('=');
        if (separator == std::string::npos || field.find('=', separator + 1) != std::string::npos) return false;
        const std::string key = field.substr(0, separator);
        const std::string value = field.substr(separator + 1);
        if (key == "after" && !seen_after) {
            if (!parse_event_cursor(value, &parsed.after)) return false;
            seen_after = true;
        } else if (key == "limit" && !seen_limit) {
            uint32_t limit = 0;
            if (!parse_unsigned(value, 64, &limit) || limit == 0) return false;
            parsed.limit = limit;
            seen_limit = true;
        } else {
            return false;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    *output = parsed;
    return true;
}

namespace {
bool flat_object(const std::string& body)
{
    bool quoted = false;
    bool escaped = false;
    bool root_seen = false;
    for (const char c : body) {
        if (quoted) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') quoted = false;
        } else if (c == '"') {
            quoted = true;
        } else if (c == '{') {
            if (root_seen) return false;
            root_seen = true;
        } else if (c == '[' || c == ']') {
            return false;
        }
    }
    return root_seen && !quoted;
}
}

bool parse_admin_json(const std::string& type, const std::string& body,
                      const std::vector<std::string>& allowed, std::map<std::string, std::string>* fields)
{
    fields->clear();
    if (type != "application/json" && type != "application/json; charset=utf-8") return false;
    if (body.empty() || body.size() > kMaxAdminBody || body.find('\0') != std::string::npos ||
        body.find("\\u0000") != std::string::npos) return false;
    // Ограничиваем глубину до рекурсивного cJSON: разрешён только плоский объект строк.
    if (!flat_object(body)) return false;
    std::unique_ptr<cJSON, decltype(&cJSON_Delete)> json(
        cJSON_ParseWithLengthOpts(body.c_str(), body.size() + 1, nullptr, true), cJSON_Delete);
    if (!json || !cJSON_IsObject(json.get())) return false;
    for (const cJSON* item = json->child; item; item = item->next) {
        if (!item->string || !cJSON_IsString(item) || !item->valuestring ||
            std::find(allowed.begin(), allowed.end(), item->string) == allowed.end() ||
            !fields->emplace(item->string, item->valuestring).second) {
            fields->clear();
            return false;
        }
    }
    return true;
}

std::string session_cookie_token(const std::string& cookies)
{
    std::string token;
    size_t start = 0;
    bool found = false;
    while (start < cookies.size()) {
        const size_t end = cookies.find(';', start);
        std::string field = cookies.substr(start, end == std::string::npos ? std::string::npos : end - start);
        const size_t first = field.find_first_not_of(" \t");
        if (first != std::string::npos) field.erase(0, first);
        const size_t split = field.find('=');
        if (field.substr(0, split) == kSessionCookie) {
            if (found || split == std::string::npos) return {};
            found = true;
            token = field.substr(split + 1);
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    if (token.size() != 64 || !std::all_of(token.begin(), token.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    })) return {};
    return token;
}
}
