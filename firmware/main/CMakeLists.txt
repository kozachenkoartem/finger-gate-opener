idf_component_register(SRCS "main.cpp"
                       INCLUDE_DIRS "."
                       REQUIRES led_strip)

target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)
