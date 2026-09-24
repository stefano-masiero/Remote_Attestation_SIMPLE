// tcp_bridge.c — TCP ↔ UART bidirectional relay for the ESP32 gateway
//
// Two FreeRTOS tasks run the relay:
//
//   tcp_server_task (prio 5, core 1)
//     Binds a listening socket on the configured TCP port, accepts one client
//     at a time, and loops: recv() from TCP → uart_bridge_write() to the
//     prover. If a second client connects while one is active, it is rejected
//     immediately.
//
//   uart_to_tcp_task (prio 5, core 1)
//     Polls uart_bridge_read() and, if an active TCP client exists, forwards
//     the bytes with send_all_locked(). On send failure it requests the server
//     task to close the client on its next recv() cycle (via the
//     s_client_close_requested flag) rather than closing the socket from a
//     different task context.
//
// Concurrency: a mutex (s_client_mutex) protects the shared client state
// (s_active_client, s_client_count, s_client_close_requested). Both tasks take
// the mutex for every access — the critical sections are short (pointer swap /
// flag read).
//
// From a security perspective, the bridge is transparent: it does not hold
// K_AUTH or K_ATTEST, does not interpret the framing, and does not modify any
// byte. End-to-end authenticity is the verifier's and prover's responsibility.

#include "tcp_bridge.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "app_config.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "uart_bridge.h"

// ---------------------------------------------------------------- Tunables ---
#define TCP_BRIDGE_LISTEN_BACKLOG 1   // only one verifier connection at a time
#define TCP_BRIDGE_RX_BUFFER_SIZE 512 // per-read buffer for TCP recv()
#define TCP_BRIDGE_UART_BUFFER_SIZE 512 // per-read buffer for UART rx
#define TCP_BRIDGE_TASK_STACK 4096
#define TCP_BRIDGE_TASK_PRIO 5
#define TCP_BRIDGE_IO_TIMEOUT_MS 200 // socket + UART read timeout

static const char *TAG = "TCP_BRIDGE";

// ------------------------------------------------------ Shared client state
// ---
static SemaphoreHandle_t s_client_mutex = NULL;
static int s_active_client = -1; // socket fd of the connected verifier, or -1
static uint16_t s_client_count =
    0; // 0 or 1 in the current single-client design
static bool s_initialized = false;
static bool s_client_close_requested =
    false; // set by uart_to_tcp on send failure

// ------------------------------------------------- Locked accessor helpers
// ---- All of these assume the caller already holds s_client_mutex.

static int active_client_get_locked(void) { return s_active_client; }

static void active_client_set_locked(int sock) {
  s_active_client = sock;
  s_client_count = (sock >= 0) ? 1 : 0;
  s_client_close_requested = false;
}

static void active_client_request_close_locked(int sock) {
  // Signal the server task to tear down the client on its next iteration.
  if (s_active_client == sock) {
    s_client_close_requested = true;
  }
}

static bool active_client_close_requested_locked(int sock) {
  return (s_active_client == sock) && s_client_close_requested;
}

// --------------------------------------------------------- Socket helpers
// -----

static void close_socket_quietly(int sock) {
  if (sock >= 0) {
    shutdown(sock, SHUT_RDWR);
    close(sock);
  }
}

static bool socket_is_wouldblock(void) {
  return errno == EAGAIN || errno == EWOULDBLOCK;
}

static void active_client_clear_if_matches(int sock) {
  // Atomically clear the active client if it is still the given socket.
  xSemaphoreTake(s_client_mutex, portMAX_DELAY);
  if (s_active_client == sock) {
    active_client_set_locked(-1);
  }
  xSemaphoreGive(s_client_mutex);
}

static int send_all_locked(int sock, const uint8_t *data, size_t len) {
  // Blocking send of the full buffer. Retries on EAGAIN; returns -1 on hard
  // error. Caller must hold s_client_mutex (the socket might be closed from
  // another context otherwise).
  size_t total = 0;

  while (total < len) {
    int sent = send(sock, data + total, len - total, 0);
    if (sent > 0) {
      total += (size_t)sent;
      continue;
    }

    if (sent < 0 && socket_is_wouldblock()) {
      continue;
    }

    return -1;
  }

  return (int)total;
}

static void configure_client_socket(int sock) {
  // Apply RX/TX timeouts so recv() and send() never block indefinitely.
  struct timeval tv = {.tv_sec = TCP_BRIDGE_IO_TIMEOUT_MS / 1000,
                       .tv_usec = (TCP_BRIDGE_IO_TIMEOUT_MS % 1000) * 1000};

  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

// ======================================================= tcp_server_task
// ======

static void tcp_server_task(void *arg) {
  // Accept loop: binds, listens, then for each accepted client enters a recv()
  // loop that forwards TCP→UART until disconnect or close request.
  const app_config_t *cfg = app_config_get();
  int listen_sock = -1;
  struct sockaddr_in listen_addr = {0};
  int reuse = 1;
  uint8_t rx_buffer[TCP_BRIDGE_RX_BUFFER_SIZE];

  (void)arg;

  listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
  if (listen_sock < 0) {
    ESP_LOGE(TAG, "socket() failed: errno=%d", errno);
    vTaskDelete(NULL);
    return;
  }

  setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  listen_addr.sin_family = AF_INET;
  listen_addr.sin_port = htons(cfg->tcp_port);
  listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(listen_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) <
      0) {
    ESP_LOGE(TAG, "bind() failed: errno=%d", errno);
    close_socket_quietly(listen_sock);
    vTaskDelete(NULL);
    return;
  }

  if (listen(listen_sock, TCP_BRIDGE_LISTEN_BACKLOG) < 0) {
    ESP_LOGE(TAG, "listen() failed: errno=%d", errno);
    close_socket_quietly(listen_sock);
    vTaskDelete(NULL);
    return;
  }

  ESP_LOGI(TAG, "TCP server listening on port %u", (unsigned)cfg->tcp_port);

  // ---- Outer loop: accept one client at a time ----
  while (1) {
    struct sockaddr_in client_addr = {0};
    socklen_t client_len = sizeof(client_addr);
    int client_sock =
        accept(listen_sock, (struct sockaddr *)&client_addr, &client_len);

    if (client_sock < 0) {
      ESP_LOGW(TAG, "accept() failed: errno=%d", errno);
      vTaskDelay(pdMS_TO_TICKS(200));
      continue;
    }

    configure_client_socket(client_sock);

    // Only one verifier at a time; reject if another is already connected.
    xSemaphoreTake(s_client_mutex, portMAX_DELAY);
    if (active_client_get_locked() >= 0) {
      xSemaphoreGive(s_client_mutex);
      ESP_LOGW(TAG, "Rejecting client: another client is already connected");
      close_socket_quietly(client_sock);
      continue;
    }

    active_client_set_locked(client_sock);
    xSemaphoreGive(s_client_mutex);

    ESP_LOGI(TAG, "Client connected");

    xSemaphoreTake(s_client_mutex, portMAX_DELAY);
    xSemaphoreGive(s_client_mutex);

    // ---- Inner loop: forward TCP → UART until disconnect or close request
    // ----
    while (1) {
      xSemaphoreTake(s_client_mutex, portMAX_DELAY);
      bool close_requested = active_client_close_requested_locked(client_sock);
      xSemaphoreGive(s_client_mutex);

      if (close_requested) {
        ESP_LOGW(TAG, "Closing client after UART->TCP send failure");
        break;
      }

      int recv_len = recv(client_sock, rx_buffer, sizeof(rx_buffer), 0);

      if (recv_len > 0) {
        ESP_LOGI(TAG, "TCP -> UART: %d bytes", recv_len);

        int written = uart_bridge_write(rx_buffer, (size_t)recv_len);
        if (written < 0) {
          ESP_LOGE(TAG, "uart_bridge_write() failed");
          break;
        }
        continue;
      }

      if (recv_len == 0) {
        ESP_LOGI(TAG, "Client disconnected");
        break;
      }

      if (socket_is_wouldblock()) {
        continue; // timeout, not an error — just loop back
      }

      ESP_LOGW(TAG, "recv() failed: errno=%d", errno);
      break;
    }

    active_client_clear_if_matches(client_sock);
    close_socket_quietly(client_sock);
  }
}

// ====================================================== uart_to_tcp_task
// ======

static void uart_to_tcp_task(void *arg) {
  // Polling loop: read whatever the prover sent on UART and forward it to the
  // active TCP client (the verifier). If no client is connected, bytes are
  // dropped.
  uint8_t uart_buffer[TCP_BRIDGE_UART_BUFFER_SIZE];

  (void)arg;

  while (1) {
    int read_len = uart_bridge_read(uart_buffer, sizeof(uart_buffer),
                                    TCP_BRIDGE_IO_TIMEOUT_MS);

    if (read_len < 0) {
      ESP_LOGW(TAG, "uart_bridge_read() failed");
      vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }

    if (read_len == 0) {
      continue; // timeout, nothing received
    }

    ESP_LOGI(TAG, "UART -> TCP: %d bytes", read_len);

    xSemaphoreTake(s_client_mutex, portMAX_DELAY);

    if (active_client_get_locked() >= 0) {
      int sock = active_client_get_locked();

      if (active_client_close_requested_locked(sock)) {
        ESP_LOGW(TAG, "Client close pending, dropping %d UART bytes", read_len);
        xSemaphoreGive(s_client_mutex);
        continue;
      }

      int sent = send_all_locked(sock, uart_buffer, (size_t)read_len);

      if (sent < 0) {
        // Don't close the socket here (wrong task context); instead signal the
        // server task to do it on its next recv() cycle.
        ESP_LOGW(TAG, "send() failed: errno=%d", errno);
        active_client_request_close_locked(sock);
        xSemaphoreGive(s_client_mutex);
        continue;
      }

      ESP_LOGI(TAG, "Sent to TCP client: %d bytes", sent);
    } else {
      ESP_LOGW(TAG, "No active TCP client, dropping %d UART bytes", read_len);
    }

    xSemaphoreGive(s_client_mutex);
  }
}

// ============================================================ Public API
// ======

void tcp_bridge_init(void) {
  if (s_initialized) {
    ESP_LOGW(TAG, "tcp_bridge_init() called more than once, ignoring");
    return;
  }

  s_client_mutex = xSemaphoreCreateMutex();
  if (s_client_mutex == NULL) {
    ESP_LOGE(TAG, "Failed to create client mutex");
    return;
  }

  // Both tasks are pinned to core 1 to keep core 0 available for the Wi-Fi
  // stack.
  xTaskCreatePinnedToCore(tcp_server_task, "tcp_server", TCP_BRIDGE_TASK_STACK,
                          NULL, TCP_BRIDGE_TASK_PRIO, NULL, 1);

  xTaskCreatePinnedToCore(uart_to_tcp_task, "uart_to_tcp",
                          TCP_BRIDGE_TASK_STACK, NULL, TCP_BRIDGE_TASK_PRIO,
                          NULL, 1);

  s_initialized = true;

  ESP_LOGI(TAG, "TCP bridge initialized");
}

bool tcp_bridge_has_client(void) {
  bool has_client;

  xSemaphoreTake(s_client_mutex, portMAX_DELAY);
  has_client = (s_active_client >= 0);
  xSemaphoreGive(s_client_mutex);

  return has_client;
}

uint16_t tcp_bridge_get_client_count(void) {
  uint16_t count;

  xSemaphoreTake(s_client_mutex, portMAX_DELAY);
  count = s_client_count;
  xSemaphoreGive(s_client_mutex);

  return count;
}
