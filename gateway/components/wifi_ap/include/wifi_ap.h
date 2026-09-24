// wifi_ap.h — SoftAP Wi-Fi interface for the ESP32 gateway
//
// Configures the ESP32 as a Wi-Fi access point so the PC verifier can connect
// without requiring an external router. The SoftAP uses WPA2-PSK if the
// configured password is >= 8 characters; otherwise it falls back to an open
// AP.

#ifndef WIFI_AP_H
#define WIFI_AP_H

#include <stdbool.h>
#include <stdint.h>

// Initialize the Wi-Fi subsystem, register event handlers, and start the
// SoftAP. Called once from app_main() before tcp_bridge_init().
void wifi_ap_init(void);

// Return true once the SoftAP has emitted WIFI_EVENT_AP_START.
bool wifi_ap_is_started(void);

// Return the current number of stations (clients) associated with the AP.
uint16_t wifi_ap_get_station_count(void);

#endif
