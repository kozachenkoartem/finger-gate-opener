#include <cstdlib>
#include <iostream>

#include "provisioning_state.hpp"

namespace {

void require(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}

void test_state_json_reports_connection_progress()
{
    fg::ProvisioningState state("192.168.4.1", "finger-gate-a31d");

    require(state.json() ==
                "{\"state\":\"ap_ready\",\"message\":\"Access point is ready\",\"sta_ip\":\"\",\"ap_ip\":\"192.168.4.1\",\"hostname\":\"finger-gate-a31d\"}",
            "initial state must describe the ready access point");

    state.connecting();
    require(state.json().find("\"state\":\"connecting\"") != std::string::npos,
            "connecting state must be visible to the browser");

    state.connected("10.0.0.24");
    require(state.json() ==
                "{\"state\":\"connected\",\"message\":\"Connected to the local network\",\"sta_ip\":\"10.0.0.24\",\"ap_ip\":\"192.168.4.1\",\"hostname\":\"finger-gate-a31d\"}",
            "connected state must expose the assigned station address");

    state.failed("Connection failed. Check Wi-Fi name and password.");
    require(state.json().find("\"state\":\"failed\"") != std::string::npos,
            "connection failure must be observable");
}

void test_form_decoder_decodes_url_encoded_credentials()
{
    const fg::FormDecodeResult result = fg::decode_wifi_form("password=secret%21&ssid=Office+Wi-Fi%202");

    require(result.ok(), "valid URL-encoded form must be accepted");
    require(result.credentials.ssid == "Office Wi-Fi 2", "SSID must decode plus and percent escapes");
    require(result.credentials.password == "secret!", "password must decode percent escapes");
}

void test_form_decoder_rejects_invalid_input()
{
    require(!fg::decode_wifi_form("password=secret").ok(), "SSID must be required");
    require(!fg::decode_wifi_form("ssid=Office%ZZ&password=secret").ok(), "invalid percent escape must be rejected");
    require(!fg::decode_wifi_form("ssid=Office&ssid=Other&password=secret").ok(), "duplicate fields must be rejected");
    require(!fg::decode_wifi_form("ssid=&password=secret").ok(), "empty SSID must be rejected");
}

}

int main()
{
    test_state_json_reports_connection_progress();
    test_form_decoder_decodes_url_encoded_credentials();
    test_form_decoder_rejects_invalid_input();
    return EXIT_SUCCESS;
}
