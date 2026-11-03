#pragma once

#include <map>
#include <string>
#include <vector>

namespace fg {
constexpr size_t kMaxAdminBody = 1024;
constexpr char kSessionCookie[] = "__Host-fg_session";

bool parse_admin_json(const std::string& content_type, const std::string& body,
                      const std::vector<std::string>& allowed_fields, std::map<std::string, std::string>* fields);
std::string session_cookie_token(const std::string& cookies);
}
