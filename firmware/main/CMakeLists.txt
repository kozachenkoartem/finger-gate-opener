idf_component_register(SRCS "main.cpp"
                             "finger_gate_model.cpp"
                              "audit_events.cpp"
                              "audit_store.cpp"
                             "auth.cpp"
                              "auth_crypto.cpp"
                              "hub_auth.cpp"
                             "api_router.cpp"
                             "http_server.cpp"
                             "tls_identity.cpp"
                             "config_store.cpp"
                             "fingerprint_task.cpp"
                             "fingerprint_controller.cpp"
                             "gate_actuator.cpp"
                             "indicator.cpp"
                             "nvs_storage.cpp"
                             "provisioning.cpp"
                             "provisioning_state.cpp"
                             "wifi_lifecycle.cpp"
                             "wifi_event_gate.cpp"
                             "user_store.cpp"
                             "r558s_driver.cpp"
                             "r558s_protocol.cpp"
                       INCLUDE_DIRS "."
                       REQUIRES esp_driver_gpio esp_driver_uart esp_driver_gptimer esp_timer esp_hw_support
                                 nvs_flash esp_event esp_netif esp_wifi esp_http_server esp_partition
                                esp_https_server mdns mbedtls json
                       EMBED_TXTFILES "../web/index.html")

target_compile_options(${COMPONENT_LIB} PRIVATE -std=gnu++17)
