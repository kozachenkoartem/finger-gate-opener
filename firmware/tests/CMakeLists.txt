cmake_minimum_required(VERSION 3.16)

project(finger_gate_protocol_tests LANGUAGES C CXX)

enable_testing()

add_executable(r558s_protocol_test
    r558s_protocol_test.cpp
    ../main/r558s_protocol.cpp)

target_compile_features(r558s_protocol_test PRIVATE cxx_std_17)
target_include_directories(r558s_protocol_test PRIVATE ../main)

add_test(NAME r558s_protocol_test COMMAND r558s_protocol_test)

add_executable(finger_gate_model_test
    finger_gate_model_test.cpp
    ../main/finger_gate_model.cpp)

target_compile_features(finger_gate_model_test PRIVATE cxx_std_17)
target_include_directories(finger_gate_model_test PRIVATE ../main)

add_test(NAME finger_gate_model_test COMMAND finger_gate_model_test)

add_executable(user_store_test
    user_store_test.cpp
    ../main/finger_gate_model.cpp
    ../main/user_store.cpp
    ../main/audit_events.cpp)

target_compile_features(user_store_test PRIVATE cxx_std_17)
target_include_directories(user_store_test PRIVATE ../main)

add_test(NAME user_store_test COMMAND user_store_test)

add_executable(provisioning_state_test
    provisioning_state_test.cpp
    ../main/provisioning_state.cpp)

target_compile_features(provisioning_state_test PRIVATE cxx_std_17)
target_include_directories(provisioning_state_test PRIVATE ../main)

add_test(NAME provisioning_state_test COMMAND provisioning_state_test)

add_executable(config_store_test
    config_store_test.cpp
    ../main/config_store.cpp
    ../main/user_store.cpp
    ../main/finger_gate_model.cpp)

target_compile_features(config_store_test PRIVATE cxx_std_17)
target_include_directories(config_store_test PRIVATE ../main)

add_test(NAME config_store_test COMMAND config_store_test)

add_executable(indicator_test
    indicator_test.cpp
    ../main/indicator.cpp)

target_compile_features(indicator_test PRIVATE cxx_std_17)
target_include_directories(indicator_test PRIVATE ../main)

add_test(NAME indicator_test COMMAND indicator_test)

set(ESP_IDF_SOURCE_PATH "$ENV{IDF_PATH}" CACHE PATH "ESP-IDF source for the production JSON parser")
if(NOT EXISTS "${ESP_IDF_SOURCE_PATH}/components/json/cJSON/cJSON.c")
    message(FATAL_ERROR "Set ESP_IDF_SOURCE_PATH or activate ESP-IDF before configuring host tests")
endif()
add_library(host_cjson STATIC "${ESP_IDF_SOURCE_PATH}/components/json/cJSON/cJSON.c")
target_include_directories(host_cjson PUBLIC "${ESP_IDF_SOURCE_PATH}/components/json/cJSON")
add_executable(api_router_test api_router_test.cpp ../main/api_router.cpp)
target_compile_features(api_router_test PRIVATE cxx_std_17)
target_include_directories(api_router_test PRIVATE ../main)
target_link_libraries(api_router_test PRIVATE host_cjson)
add_test(NAME api_router_test COMMAND api_router_test)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_executable(auth_test
    auth_test.cpp
    ../main/auth.cpp
    ../main/auth_crypto.cpp
    ../main/user_store.cpp
    ../main/finger_gate_model.cpp)

target_compile_features(auth_test PRIVATE cxx_std_17)
target_include_directories(auth_test PRIVATE ../main)
target_link_libraries(auth_test PRIVATE OpenSSL::Crypto)
target_link_options(auth_test PRIVATE "-Wl,--wrap=RAND_bytes" "-Wl,--wrap=PKCS5_PBKDF2_HMAC")

add_test(NAME auth_test COMMAND auth_test)

add_executable(fingerprint_controller_test
    fingerprint_controller_test.cpp
    ../main/fingerprint_controller.cpp
    ../main/user_store.cpp
    ../main/finger_gate_model.cpp)

target_compile_features(fingerprint_controller_test PRIVATE cxx_std_17)
target_include_directories(fingerprint_controller_test PRIVATE ../main)

add_test(NAME fingerprint_controller_test COMMAND fingerprint_controller_test)

add_executable(wifi_state_test wifi_state_test.cpp
    ../main/wifi_lifecycle.cpp ../main/wifi_event_gate.cpp
    ../main/config_store.cpp ../main/user_store.cpp ../main/finger_gate_model.cpp)
target_compile_features(wifi_state_test PRIVATE cxx_std_17)
target_include_directories(wifi_state_test PRIVATE ../main)
add_test(NAME wifi_state_test COMMAND wifi_state_test)

find_program(NODE_EXECUTABLE node)
if(NODE_EXECUTABLE)
    add_test(NAME web_network_test COMMAND "${NODE_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/web_network_test.mjs" "${CMAKE_CURRENT_SOURCE_DIR}/../web/index.html")
endif()
