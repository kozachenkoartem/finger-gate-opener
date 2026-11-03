idf_component_register(SRCS "main.cpp"
                             "finger_gate_model.cpp"
                             "r558s_driver.cpp"
                             "r558s_protocol.cpp"
                       INCLUDE_DIRS "."
                       REQUIRES esp_driver_gpio esp_driver_uart esp_timer)

target_compile_options(${COMPONENT_LIB} PRIVATE -std=gnu++17)
