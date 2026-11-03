#include "api_router.hpp"
#include <cstdlib>
#include <iostream>
#include "cJSON.h"

namespace {
size_t allocations = 0;
void* counted_malloc(size_t size) { ++allocations; return std::malloc(size); }
}

void require(bool condition, const char* message)
{
    if (!condition) { std::cerr << message << '\n'; std::exit(EXIT_FAILURE); }
}

int main()
{
    std::map<std::string, std::string> fields;
    const std::vector<std::string> allowed{"username", "password"};
    require(fg::parse_admin_json("application/json", R"({"username":"admin","password":"hello\"world"})", allowed, &fields), "JSON escaped passwords accepted");
    require(fields.at("password") == "hello\"world", "escaped quotes decoded");
    for (const auto* body : {"null", "[]", "{", "{}garbage", "{\"username\":1}", "{\"x\":\"y\"}",
                             "{\"username\":\"a\",\"username\":\"b\"}", "{\"password\":\"a\\u0000b\"}"}) {
        require(!fg::parse_admin_json("application/json", body, allowed, &fields), "malformed, duplicate or invalid JSON rejected");
    }
    require(!fg::parse_admin_json("text/plain", "{}", allowed, &fields), "unsupported content type rejected");
    require(!fg::parse_admin_json("application/json", std::string(1025, ' '), allowed, &fields), "oversized request rejected");
    cJSON_Hooks hooks{counted_malloc, std::free};
    cJSON_InitHooks(&hooks);
    require(!fg::parse_admin_json("application/json", std::string(1024, '['), allowed, &fields), "malformed deep array rejected");
    require(allocations < 8, "deep untrusted input must be rejected before recursive JSON allocation");
    allocations = 0;
    require(!fg::parse_admin_json("application/json", "{\"password\":" + std::string(400, '[') + "0" + std::string(400, ']') + "}", allowed, &fields), "valid deep nested array rejected");
    require(allocations < 8, "nested fields must not enter recursive parsing");
    cJSON_InitHooks(nullptr);
    require(fg::parse_admin_json("application/json", R"({"password":"[ { \" } ]"})", allowed, &fields), "brackets inside quoted passwords remain allowed");
    const std::string token(64, 'a');
    require(fg::session_cookie_token("other=1; __Host-fg_session=" + token) == token, "exact cookie extracted");
    require(fg::session_cookie_token("prefix__Host-fg_session=" + token).empty(), "cookie substring rejected");
    require(fg::session_cookie_token("__Host-fg_session=" + token + "; __Host-fg_session=" + token).empty(), "duplicate cookies rejected");
    require(fg::session_cookie_token("__Host-fg_session=bad").empty(), "short token rejected");
    return EXIT_SUCCESS;
}
