// uart_bridge.c — UART driver wrapper for the ESP32 ↔ STM32 link
//
// Installs the ESP-IDF UART driver on the peripheral and pins selected in
// app_config (typically UART1, since UART0 is the console). The driver's own
// ring buffers (2 KB RX + 2 KB TX) decouple the TCP bridge tasks from the
// hardware FIFO, so short bursts of attestation traffic (request ≈ 89 B,
// response ≈ 75–115 B) never overflow.
//
// This module does NOT interpret the data: it is a transparent byte pipe.

#include "uart_bridge.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "app_config.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define UART_RX_BUFFER_SIZE 2048
#define UART_TX_BUFFER_SIZE 2048

static const char *TAG = "UART_BRIDGE";
static uart_port_t s_uart_num;
static bool s_initialized = false;

void uart_bridge_init(void) {
  const app_config_t *cfg = app_config_get();

  // 8N1, no flow control — matches the STM32 prover's UART configuration.
  uart_config_t uart_cfg = {
      .baud_rate = cfg->uart_baud_rate,
      .data_bits = UART_DATA_8_BITS,
      .parity = UART_PARITY_DISABLE,
      .stop_bits = UART_STOP_BITS_1,
      .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
      .rx_flow_ctrl_thresh = 0,
      .source_clk = UART_SCLK_DEFAULT,
  };

  s_uart_num = (uart_port_t)cfg->uart_port_num;

  // Install the driver with separate RX/TX ring buffers; no event queue needed
  // because the bridge tasks poll with uart_read_bytes() timeouts.
  ESP_ERROR_CHECK(uart_driver_install(s_uart_num, UART_RX_BUFFER_SIZE,
                                      UART_TX_BUFFER_SIZE, 0, NULL, 0));

  ESP_ERROR_CHECK(uart_param_config(s_uart_num, &uart_cfg));

  ESP_ERROR_CHECK(uart_set_pin(s_uart_num, cfg->uart_tx_pin, cfg->uart_rx_pin,
                               UART_PIN_NO_CHANGE, // RTS not used
                               UART_PIN_NO_CHANGE  // CTS not used
                               ));

  s_initialized = true;

  ESP_LOGI(TAG, "UART initialized: port=%d tx=%d rx=%d baud=%d",
           (int)s_uart_num, cfg->uart_tx_pin, cfg->uart_rx_pin,
           cfg->uart_baud_rate);
}

int uart_bridge_write(const uint8_t *data, size_t len) {
  if (!s_initialized || data == NULL || len == 0) {
    return 0;
  }

  int written = uart_write_bytes(s_uart_num, data, len);

  if (written < 0) {
    ESP_LOGE(TAG, "uart_write_bytes failed");
    return -1;
  }

  // Block until the hardware TX FIFO has drained so the prover sees the
  // complete frame before the caller processes a potential response.
  uart_wait_tx_done(s_uart_num, pdMS_TO_TICKS(1000));

  ESP_LOGI(TAG, "UART TX: %d bytes", written);

  return written;
}

int uart_bridge_read(uint8_t *data, size_t max_len, uint32_t timeout_ms) {
  if (!s_initialized || data == NULL || max_len == 0) {
    return 0;
  }

  int read =
      uart_read_bytes(s_uart_num, data, max_len, pdMS_TO_TICKS(timeout_ms));

  if (read < 0) {
    ESP_LOGE(TAG, "uart_read_bytes failed");
    return -1;
  }

  if (read > 0) {
    ESP_LOGI(TAG, "UART RX: %d bytes", read);
  }

  return read;
}
