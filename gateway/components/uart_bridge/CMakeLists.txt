idf_component_register(
    SRCS "uart_bridge.c"
    INCLUDE_DIRS "include"
    REQUIRES app_config esp_driver_uart
)
