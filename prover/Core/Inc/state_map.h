// state_map.h — memory-region map, protected state structures, and region
// accessors
//
// This module owns the three privileged RAM structures that live in RAM_PRIV
// (see report §2.6 / Figure 5 and STM32H503xx_FLASH.ld):
//
//   .attest_state   — attestation metadata: magic, lifecycle, security/protocol
//   flags.
//                     Excluded from every profile digest because it changes at
//                     runtime.
//   .attest_cfg     — configuration shadow: a snapshot of HW register state
//   (UART config,
//                     HASH config, clock frequencies, ICACHE, flash latency)
//                     refreshed under IRQ mask before Profile 3 measurement.
//   .attest_secure  — persistent secure runtime: the monotonic last_counter
//   that enforces
//                     replay protection. Excluded from all profiles.
//
// It also exposes the four region accessors that the attestation engine uses to
// map a profile ID to a set of (start, length) ranges for hashing:
//   Profile 1: main flash + privileged flash
//   Profile 2: Profile 1 + .app_attested_ram
//   Profile 3: Profile 2 + .attest_cfg
//
// Region boundaries come from linker-script symbols (__attest_flash_start__,
// etc.) and are validated at runtime against the known address map.

#ifndef STATE_MAP_H
#define STATE_MAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---- Generic measured-region descriptor ----
typedef struct {
  const uint8_t *start;
  size_t length;
} state_map_region_t;

// ---- Lifecycle values for .attest_state ----
typedef enum {
  STATE_MAP_LIFECYCLE_BOOTING = 1u,
  STATE_MAP_LIFECYCLE_READY = 2u,
  STATE_MAP_LIFECYCLE_FAULT = 3u,
} state_map_lifecycle_t;

// ---- Security-flag bits (.attest_state.security_flags) ----
enum {
  STATE_MAP_SECFLAG_COUNTER_ENFORCED = (1u << 0),
  STATE_MAP_SECFLAG_HASH_HW = (1u << 1),
  STATE_MAP_SECFLAG_HMAC_HW = (1u << 2),
  STATE_MAP_SECFLAG_LOCAL_VS_DEBUG =
      (1u << 3), // set when ATTESTATION_INCLUDE_LOCAL_VS_DEBUG=1
  STATE_MAP_SECFLAG_CFG_SNAPSHOT = (1u << 4),
};

// ---- Protocol-flag bits (.attest_state.protocol_flags) ----
enum {
  STATE_MAP_PROTOFLAG_UART_READY = (1u << 0),
  STATE_MAP_PROTOFLAG_PARSER_READY = (1u << 1),
};

// ---- Attestation metadata (.attest_state section, excluded from all profiles)
// ----
typedef struct {
  uint32_t magic; // "ATTS"
  uint32_t layout_version;
  uint32_t lifecycle_state;
  uint32_t security_flags;
  uint32_t protocol_flags;
  uint32_t config_version;
  uint32_t feature_mask;
  uint32_t reserved;
} state_map_attest_state_t;

// ---- Configuration shadow (.attest_cfg section, measured only in Profile 3)
// ----
typedef struct {
  uint32_t magic; // "CFGS"
  uint32_t layout_version;
  uint32_t supported_protocol_version;
  uint32_t supported_profile_mask;
  uint32_t uart_baudrate;
  uint32_t uart_frame_cfg; // packed word-length / parity / stop-bits / mode
  uint32_t hash_cfg;       // packed algorithm / data-type
  uint32_t platform_cfg;   // ICACHE enable, debug-VS flag
  uint32_t sysclk_hz;
  uint32_t hclk_hz;
  uint32_t flash_wait_states;
  uint32_t flash_write_delay;
} state_map_config_shadow_t;

// ---- Secure runtime (.attest_secure section, excluded from all profiles) ----
typedef struct {
  uint32_t magic; // "SECR"
  uint32_t layout_version;
  uint32_t last_counter; // monotonic counter for replay protection
  uint32_t reserved;
} state_map_secure_runtime_t;

// ---- Initialization (called once from main before entering unprivileged mode)
// ----
void state_map_attest_state_init(void);
void state_map_config_shadow_init(void);
void state_map_secure_runtime_init(void);

// ---- Runtime updates ----
void state_map_attest_state_set_lifecycle(uint32_t lifecycle);
void state_map_attest_state_set_protocol_flags(uint32_t flags);
void state_map_attest_state_set_security_flags(uint32_t flags);
// Snapshot HW registers into the config shadow (called under IRQ mask for
// Profile 3).
void state_map_config_shadow_refresh_from_hw(void);

// ---- Read-only accessors ----
const state_map_attest_state_t *state_map_get_attest_state(void);
const state_map_config_shadow_t *state_map_get_config_shadow(void);

// ---- Secure counter (privileged-only, accessed from the attestation engine)
// ----
uint32_t state_map_secure_get_last_counter(void);
void state_map_secure_set_last_counter(uint32_t counter);

// ---- Profile-to-region mapping (privileged-only, used by
// attestation_compute_valid_state) ----
bool state_map_get_profile1_flash_region(state_map_region_t *region);
bool state_map_get_profile1_flash_priv_region(state_map_region_t *region);
bool state_map_get_profile2_ram_region(state_map_region_t *region);
bool state_map_get_profile3_config_region(state_map_region_t *region);

#ifdef __cplusplus
}
#endif

#endif /* STATE_MAP_H */
