idf_component_register(SRCS "app_main.c" "crypto_manager.c" "client_node.c" "network_shaper.c"
                            "kem.c" "indcpa.c" "poly.c" "polyvec.c" "ntt.c" "reduce.c" "cbd.c" "verify.c" "symmetric-shake.c" "fips202.c"
                       INCLUDE_DIRS "."
                       REQUIRES mbedtls cjson esp_timer)

target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-error=enum-compare")