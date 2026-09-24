// wifi_ap.c — SoftAP driver for the ESP32 gateway
//
// Sets up the ESP32 as a Wi-Fi access point using the SSID and password from
// app_config. The verifier connects to this AP as a station, then opens a TCP
// connection to the bridge. The gateway is the network entry point of the
// attestation system (see report §2.3).
//
// A single event handler tracks AP start/stop and station connect/disconnect
// events; the station count is exposed so app_main() can log it at boot.

#include "wifi_ap.h"

#include <string.h>

#include "app_config.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_wifi.h"

static const char *TAG = "WIFI_AP";

static bool s_initialized = false;
static bool s_started = false;
static uint16_t s_sta_count = 0;

static esp_event_handler_instance_t s_any_wifi_handler;

// -------------------------------------------------------- Event handler
// -------

static void wifi_ap_event_handler(void *arg, esp_event_base_t event_base,
                                  int32_t event_id, void *event_data) {
  (void)arg;

  if (event_base != WIFI_EVENT) {
    return;
  }

  switch (event_id) {
  case WIFI_EVENT_AP_START:
    s_started = true;
    ESP_LOGI(TAG, "SoftAP started");
    break;

  case WIFI_EVENT_AP_STOP:
    s_started = false;
    s_sta_count = 0;
    ESP_LOGI(TAG, "SoftAP stopped");
    break;

  case WIFI_EVENT_AP_STACONNECTED: {
    const wifi_event_ap_staconnected_t *ev =
        (const wifi_event_ap_staconnected_t *)event_data;

    s_sta_count++;

    ESP_LOGI(TAG, "Station connected: " MACSTR ", aid=%d, total_sta=%u",
             MAC2STR(ev->mac), ev->aid, (unsigned)s_sta_count);
    break;
  }

  case WIFI_EVENT_AP_STADISCONNECTED: {
    const wifi_event_ap_stadisconnected_t *ev =
        (const wifi_event_ap_stadisconnected_t *)event_data;

    if (s_sta_count > 0) {
      s_sta_count--;
    }

    ESP_LOGI(TAG, "Station disconnected: " MACSTR ", aid=%d, total_sta=%u",
             MAC2STR(ev->mac), ev->aid, (unsigned)s_sta_count);
    break;
  }

  default:
    break;
  }
}

// ============================================================ Public API
// ======

void wifi_ap_init(void) {
  const app_config_t *cfg = app_config_get();
  wifi_init_config_t wifi_init_cfg = WIFI_INIT_CONFIG_DEFAULT();
  wifi_config_t ap_cfg = {0};
  size_t password_len;

  if (s_initialized) {
    ESP_LOGW(TAG, "wifi_ap_init() called more than once, ignoring");
    return;
  }

  password_len = strlen(cfg->wifi_password);

  // Standard ESP-IDF Wi-Fi init sequence: netif → event loop → default AP
  // netif.
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  esp_netif_create_default_wifi_ap();

  // Register a catch-all Wi-Fi event handler (AP_START, AP_STOP,
  // STA_CONNECTED…).
  ESP_ERROR_CHECK(esp_event_handler_instance_register(
      WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_ap_event_handler, NULL,
      &s_any_wifi_handler));

  ESP_ERROR_CHECK(esp_wifi_init(&wifi_init_cfg));
  ESP_ERROR_CHECK(
      esp_wifi_set_storage(WIFI_STORAGE_RAM)); // don't persist config to NVS
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));

  // Copy SSID and password from the runtime config into the Wi-Fi config
  // struct.
  strncpy((char *)ap_cfg.ap.ssid, cfg->wifi_ssid, sizeof(ap_cfg.ap.ssid) - 1);
  ap_cfg.ap.ssid_len = strlen(cfg->wifi_ssid);

  strncpy((char *)ap_cfg.ap.password, cfg->wifi_password,
          sizeof(ap_cfg.ap.password) - 1);

  ap_cfg.ap.channel = 1;
  ap_cfg.ap.max_connection = 4;
  ap_cfg.ap.pmf_cfg.required = false;

  // WPA2-PSK requires >= 8-character passphrase; fall back to open if shorter.
  if (password_len >= 8) {
    ap_cfg.ap.authmode = WIFI_AUTH_WPA2_PSK;
  } else {
    ap_cfg.ap.authmode = WIFI_AUTH_OPEN;
    memset(ap_cfg.ap.password, 0, sizeof(ap_cfg.ap.password));
    ESP_LOGW(TAG, "Password shorter than 8 chars: starting OPEN AP");
  }

  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));
  ESP_ERROR_CHECK(esp_wifi_start());

  s_initialized = true;

  ESP_LOGI(TAG, "SoftAP configured: SSID=%s, auth=%s, channel=%u, max_conn=%u",
           cfg->wifi_ssid,
           (ap_cfg.ap.authmode == WIFI_AUTH_OPEN) ? "OPEN" : "WPA2-PSK",
           (unsigned)ap_cfg.ap.channel, (unsigned)ap_cfg.ap.max_connection);
}

bool wifi_ap_is_started(void) { return s_started; }

uint16_t wifi_ap_get_station_count(void) { return s_sta_count; }
