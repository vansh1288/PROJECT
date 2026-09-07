idf_component_register(SRCS "app_main.c"
                       "crypto_manager.c"
                       "client_node.c"
                       "network_shaper.c"
                       INCLUDE_DIRS "."
                       REQUIRES mbedtls cjson freertos esp_system nvs_flash esp_event esp_netif esp_wifi protobuf-c)