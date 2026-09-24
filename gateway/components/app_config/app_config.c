// app_config.c — Kconfig-to-struct loader for the ESP32 gateway
//
// Reads the CONFIG_APP_* values baked into sdkconfig at build time and copies
// them into a single app_config_t instance. The struct is populated once at
// boot and then treated as immutable; every other component reads it through
// the app_config_get() accessor.

#include "app_config.h"
#include "esp_log.h"
#include "sdkconfig.h"

static const char *TAG = "APP_CONFIG";
static app_config_t g_app_config;

void app_config_init(void) {
  g_app_config.wifi_ssid = CONFIG_APP_WIFI_SSID;
  g_app_config.wifi_password = CONFIG_APP_WIFI_PASSWORD;
  g_app_config.tcp_port = (uint16_t)CONFIG_APP_TCP_PORT;
  g_app_config.uart_port_num = CONFIG_APP_UART_PORT_NUM;
  g_app_config.uart_tx_pin = CONFIG_APP_UART_TX_PIN;
  g_app_config.uart_rx_pin = CONFIG_APP_UART_RX_PIN;
  g_app_config.uart_baud_rate = CONFIG_APP_UART_BAUD_RATE;

  ESP_LOGI(TAG, "Config loaded: SSID=%s, TCP=%u, UART%d TX=%d RX=%d BAUD=%d",
           g_app_config.wifi_ssid, (unsigned)g_app_config.tcp_port,
           g_app_config.uart_port_num, g_app_config.uart_tx_pin,
           g_app_config.uart_rx_pin, g_app_config.uart_baud_rate);
}

const app_config_t *app_config_get(void) { return &g_app_config; }
