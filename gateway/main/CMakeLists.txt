idf_component_register(
    SRCS "app_main.c"
    INCLUDE_DIRS "."
    REQUIRES app_config wifi_ap uart_bridge tcp_bridge nvs_flash
)
