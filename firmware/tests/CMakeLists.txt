cmake_minimum_required(VERSION 3.16)

project(finger_gate_protocol_tests LANGUAGES CXX)

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
