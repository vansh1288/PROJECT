idf_component_register(SRCS "app_main.c" "crypto_manager.c" "client_node.c" "network_shaper.c"
                       INCLUDE_DIRS "."
                       REQUIRES mbedtls cjson esp_timer)

target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-error=enum-compare")