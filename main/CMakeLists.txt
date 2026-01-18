idf_component_register(
    SRCS "main.c" "rampart_ble.c"
    INCLUDE_DIRS "."
    REQUIRES rampart_crypto
    PRIV_REQUIRES nvs_flash bt
)
