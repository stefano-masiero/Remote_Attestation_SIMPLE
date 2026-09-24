// uart_bridge.h — UART interface toward the STM32 prover
//
// Thin wrapper around the ESP-IDF UART driver that the TCP bridge uses to relay
// attestation frames to and from the prover. All configuration (pin-out, baud
// rate) comes from app_config at init time; after that, the bridge tasks only
// call uart_bridge_write() and uart_bridge_read().

#ifndef UART_BRIDGE_H
#define UART_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

// Configure and install the UART driver using the current app_config settings.
// Called once from app_main(), before tcp_bridge_init().
void uart_bridge_init(void);

// Synchronously write `len` bytes to the prover over UART.
// Blocks until the TX FIFO is drained (uart_wait_tx_done).
// Returns the number of bytes written, or -1 on failure.
int uart_bridge_write(const uint8_t *data, size_t len);

// Read up to `max_len` bytes from the prover, blocking for at most
// `timeout_ms`. Returns the number of bytes read (0 if the timeout expired), or
// -1 on failure.
int uart_bridge_read(uint8_t *data, size_t max_len, uint32_t timeout_ms);

#endif
