idf_component_register(
    SRCS "tcp_bridge.c"
    INCLUDE_DIRS "include"
    REQUIRES lwip app_config uart_bridge
)
