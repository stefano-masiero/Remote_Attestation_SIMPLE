// app_config.h — runtime configuration container for the ESP32 gateway
//
// All tuneable parameters (Wi-Fi SSID/password, TCP listen port, UART pin-out
// and baud rate) are pulled from the ESP-IDF Kconfig system at build time and
// exposed through a single read-only struct so that every component uses the
// same values without scattering CONFIG_APP_* macros across the codebase.

#ifndef APP_CONFIG_H
#define APP_CONFIG_H

#include <stdint.h>

typedef struct {
  const char *wifi_ssid;     // SoftAP network name
  const char *wifi_password; // WPA2-PSK passphrase (open AP if < 8 chars)
  uint16_t tcp_port;         // TCP listen port for the verifier connection
  int uart_port_num;         // ESP-IDF UART peripheral index (0, 1, or 2)
  int uart_tx_pin;           // GPIO number for UART TX toward the STM32
  int uart_rx_pin;           // GPIO number for UART RX from the STM32
  int uart_baud_rate;        // UART baud rate (must match the prover firmware)
} app_config_t;

// Populate the global config from Kconfig values. Called once at boot from
// app_main().
void app_config_init(void);

// Return a pointer to the (immutable) global config. Safe to call from any
// task.
const app_config_t *app_config_get(void);

#endif
