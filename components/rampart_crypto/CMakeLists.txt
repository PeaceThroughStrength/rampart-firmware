idf_component_register(SRCS "rampart_crypto.c"
                       INCLUDE_DIRS "include"
                       REQUIRES mbedtls nvs_flash esp_system)
