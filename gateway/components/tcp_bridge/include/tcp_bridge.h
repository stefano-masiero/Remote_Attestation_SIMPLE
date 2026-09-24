// tcp_bridge.h — TCP server ↔ UART bidirectional relay
//
// Spawns two FreeRTOS tasks that form the core of the gateway:
//   tcp_server_task : listens for one TCP client (the verifier), reads from the
//                     socket and writes to the UART (toward the prover).
//   uart_to_tcp_task: reads from the UART and sends back to the active TCP
//   client.
//
// Only one client is served at a time; additional connections are rejected.
// The bridge is purely transparent — it neither parses nor modifies the
// attestation protocol frames that pass through it (see report §2.3).

#ifndef TCP_BRIDGE_H
#define TCP_BRIDGE_H

#include <stdbool.h>
#include <stdint.h>

// Create the mutex and spawn the server + forwarding tasks.
// Requires uart_bridge_init() and wifi_ap_init() to have been called first.
void tcp_bridge_init(void);

// Return true if a TCP client (the verifier) is currently connected.
bool tcp_bridge_has_client(void);

// Return the number of active TCP clients (0 or 1 in the current design).
uint16_t tcp_bridge_get_client_count(void);

#endif
