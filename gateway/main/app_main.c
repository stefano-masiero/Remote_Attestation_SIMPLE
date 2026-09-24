// app_main.c — ESP32 gateway entry point
//
// This is the top-level application for the ESP32 Wi-Fi/UART gateway node.
// The gateway sits between the PC verifier and the STM32 prover and acts as a
// transparent TCP–UART relay: it exposes a SoftAP, accepts one TCP client (the
// verifier), and forwards every byte bidirectionally over UART to the prover.
// It does NOT parse, interpret, or modify attestation messages and does NOT
// hold any cryptographic material — authentication remains end-to-end between
// verifier and prover (see report §2.3).
//
// Boot sequence:
//   1) NVS init (required by the Wi-Fi driver).
//   2) app_config_init() — loads Kconfig-derived settings (SSID, TCP port, UART
//   pins…). 3) wifi_ap_init()    — starts the SoftAP. 4) uart_bridge_init()—
//   configures the UART port toward the STM32. 5) tcp_bridge_init() — spawns
//   the TCP server + UART→TCP forwarding tasks.
//
// After init, all work is done by FreeRTOS tasks; app_main() returns and the
// idle task reclaims its stack.

#include "app_config.h"
#include "esp_err.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "tcp_bridge.h"
#include "uart_bridge.h"
#include "wifi_ap.h"
#include <string.h>

static const char *TAG = "APP";

static void init_nvs(void) {
  // Initialize NVS; erase and retry if the partition is full or has an
  // incompatible format (common after a full reflash or partition-table
  // change).
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
      ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);
}

void app_main(void) {
  const app_config_t *cfg;

  ESP_LOGI(TAG, "Starting esp32 gateway");

  init_nvs();
  app_config_init();

  cfg = app_config_get();
  ESP_LOGI(
      TAG,
      "Runtime config -> SSID=%s | TCP=%u | UART%d | TX=%d | RX=%d | BAUD=%d",
      cfg->wifi_ssid, (unsigned)cfg->tcp_port, cfg->uart_port_num,
      cfg->uart_tx_pin, cfg->uart_rx_pin, cfg->uart_baud_rate);

  // Order matters: Wi-Fi must be up before TCP can listen, and UART must be
  // ready before the bridge tasks start forwarding bytes.
  wifi_ap_init();
  uart_bridge_init();
  tcp_bridge_init();

  ESP_LOGI(TAG, "All modules initialized | wifi_started=%d | sta_count=%u",
           wifi_ap_is_started(), (unsigned)wifi_ap_get_station_count());
}
