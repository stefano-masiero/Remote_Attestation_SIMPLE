idf_component_register(
    SRCS "wifi_ap.c"
    INCLUDE_DIRS "include"
    REQUIRES app_config esp_wifi esp_event esp_netif
)
