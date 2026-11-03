idf_component_register(SRCS "main.cpp"
                             "finger_gate_model.cpp"
                             "audit_events.cpp"
                             "nvs_storage.cpp"
                             "user_store.cpp"
                             "r558s_driver.cpp"
                             "r558s_protocol.cpp"
                       INCLUDE_DIRS "."
                       REQUIRES esp_driver_gpio esp_driver_uart esp_timer nvs_flash)

target_compile_options(${COMPONENT_LIB} PRIVATE -std=gnu++17)
