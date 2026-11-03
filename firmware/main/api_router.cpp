#include "api_router.hpp"

#include <algorithm>
#include <memory>
#include "cJSON.h"

namespace fg {
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
