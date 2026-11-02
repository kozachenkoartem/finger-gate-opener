idf_component_register(SRCS "main.cpp"
                       INCLUDE_DIRS "."
                       REQUIRES led_strip)

target_compile_options(${COMPONENT_LIB} PRIVATE -std=gnu++17)
