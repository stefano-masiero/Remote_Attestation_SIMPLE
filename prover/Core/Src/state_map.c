// state_map.c — protected-RAM structures, region accessors, and config shadow
//
// This module manages the three privileged RAM structures (see report §2.6 /
// Figure 5):
//   .attest_state   — attestation metadata (lifecycle, security/protocol
//   flags). .attest_cfg     — HW config shadow, refreshed before Profile 3
//   measurement. .attest_secure  — monotonic counter for replay protection.
//
// All three live in RAM_PRIV (0x20004000, 512 B) and are MPU/GTZC-protected as
// privileged-only. They are deliberately EXCLUDED from every profile digest
// because their contents change at runtime.
//
// The four profile-to-region accessor functions resolve linker-script symbols
// (__attest_flash_start__, __app_attested_ram_start__, etc.) into (start,
// length) descriptors that the attestation engine feeds to crypto_sha256().

#include "state_map.h"
#include "attestation.h"
#include "main.h"
#include "privileged_sections.h"
#include "protocol.h"

#include <stddef.h>
#include <stdint.h>

// ---- Linker-script symbols (see STM32H503xx_FLASH.ld) ----
extern uint8_t __attest_flash_start__[];
extern uint8_t __attest_flash_end__[];
extern uint8_t __attest_flash_priv_start__[];
extern uint8_t __attest_flash_priv_end__[];
extern uint8_t __attest_state_start__[];
extern uint8_t __attest_state_end__[];
extern uint8_t __attest_cfg_start__[];
extern uint8_t __attest_cfg_end__[];
extern uint8_t __attest_secure_start__[];
extern uint8_t __attest_secure_end__[];
extern uint8_t __app_ram_start__[];
extern uint8_t __app_ram_end__[];
extern uint8_t __attest_ram_priv_start__[];
extern uint8_t __attest_ram_priv_limit__[];
extern uint8_t __app_attested_ram_start__[];
extern uint8_t __app_attested_ram_end__[];

#define STATE_MAP_FLASH_BASE_ADDR ((uintptr_t)0x08000000u)

// ---- Magic values for structure identification ----
#define STATE_MAP_ATTEST_MAGIC 0x41545453UL /* "ATTS" */
#define STATE_MAP_ATTEST_LAYOUT_VERSION 0x00000002UL
#define STATE_MAP_ATTEST_CONFIG_VERSION 0x00000002UL
#define STATE_MAP_ATTEST_FEATURE_MASK 0x00000007UL /* profiles 1+2+3 */

#define STATE_MAP_CFG_MAGIC 0x43464753UL /* "CFGS" */
#define STATE_MAP_CFG_LAYOUT_VERSION 0x00000002UL
#define STATE_MAP_CFG_PROFILE_MASK 0x00000007UL

#define STATE_MAP_SECURE_MAGIC 0x53454352UL /* "SECR" */
#define STATE_MAP_SECURE_LAYOUT_VERSION 0x00000001UL

// ---- Section-placed instances ----
static volatile state_map_attest_state_t g_attest_state
    __attribute__((section(".attest_state"), aligned(4), used));

static volatile state_map_config_shadow_t g_config_shadow
    __attribute__((section(".attest_cfg"), aligned(4), used));

static volatile state_map_secure_runtime_t g_secure_runtime
    __attribute__((section(".attest_secure"), aligned(4), used));

// ============================================================ Config packers
// =====

ATTEST_PRIV_CODE static uint32_t state_map_pack_uart_frame_cfg(void) {
  // Pack UART word-length, parity, stop-bits and mode into one 32-bit word.
  return (((uint32_t)huart1.Init.WordLength & 0xFFu)) |
         (((uint32_t)huart1.Init.Parity & 0xFFu) << 8) |
         (((uint32_t)huart1.Init.StopBits & 0xFFu) << 16) |
         (((uint32_t)huart1.Init.Mode & 0xFFu) << 24);
}

ATTEST_PRIV_CODE static uint32_t state_map_pack_hash_cfg(void) {
  // Pack HASH algorithm and data-type selection into one 32-bit word.
  return (((uint32_t)hhash.Init.Algorithm & 0xFFFFu)) |
         (((uint32_t)hhash.Init.DataType & 0xFFFFu) << 16);
}

ATTEST_PRIV_CODE static uint32_t state_map_pack_platform_cfg(void) {
  // Platform capability flags: ICACHE on/off, debug-VS flag.
  uint32_t value = 0u;

  if ((ICACHE->CR & ICACHE_CR_EN) != 0u) {
    value |= (1u << 0);
  }

#if (ATTESTATION_INCLUDE_LOCAL_VS_DEBUG == 1u)
  value |= (1u << 1);
#endif

  return value;
}

// ============================================================ Initialization
// =====

void state_map_attest_state_init(void) {
  // Populate .attest_state with boot-time metadata. Called once from main().
  uint32_t sec_flags = 0u;

  sec_flags |= STATE_MAP_SECFLAG_COUNTER_ENFORCED;
  sec_flags |= STATE_MAP_SECFLAG_HASH_HW;
  sec_flags |= STATE_MAP_SECFLAG_HMAC_HW;
  sec_flags |= STATE_MAP_SECFLAG_CFG_SNAPSHOT;

#if (ATTESTATION_INCLUDE_LOCAL_VS_DEBUG == 1u)
  sec_flags |= STATE_MAP_SECFLAG_LOCAL_VS_DEBUG;
#endif

  g_attest_state.magic = STATE_MAP_ATTEST_MAGIC;
  g_attest_state.layout_version = STATE_MAP_ATTEST_LAYOUT_VERSION;
  g_attest_state.lifecycle_state = STATE_MAP_LIFECYCLE_BOOTING;
  g_attest_state.security_flags = sec_flags;
  g_attest_state.protocol_flags = 0u;
  g_attest_state.config_version = STATE_MAP_ATTEST_CONFIG_VERSION;
  g_attest_state.feature_mask = STATE_MAP_ATTEST_FEATURE_MASK;
  g_attest_state.reserved = 0u;
}

void state_map_config_shadow_init(void) {
  // Zero out the config shadow, then populate it from HW. Called once from
  // main().
  g_config_shadow.magic = STATE_MAP_CFG_MAGIC;
  g_config_shadow.layout_version = STATE_MAP_CFG_LAYOUT_VERSION;
  g_config_shadow.supported_protocol_version = PROTOCOL_VERSION;
  g_config_shadow.supported_profile_mask = STATE_MAP_CFG_PROFILE_MASK;

  g_config_shadow.uart_baudrate = 0u;
  g_config_shadow.uart_frame_cfg = 0u;
  g_config_shadow.hash_cfg = 0u;
  g_config_shadow.platform_cfg = 0u;
  g_config_shadow.sysclk_hz = 0u;
  g_config_shadow.hclk_hz = 0u;
  g_config_shadow.flash_wait_states = 0u;
  g_config_shadow.flash_write_delay = 0u;

  state_map_config_shadow_refresh_from_hw();
}

void state_map_secure_runtime_init(void) {
  // Initialize the secure counter. If the RAM_PRIV region still holds a valid
  // structure from a previous boot (warm reset), keep the counter intact so
  // replays across resets are still blocked.
  if ((g_secure_runtime.magic != STATE_MAP_SECURE_MAGIC) ||
      (g_secure_runtime.layout_version != STATE_MAP_SECURE_LAYOUT_VERSION)) {
    g_secure_runtime.magic = STATE_MAP_SECURE_MAGIC;
    g_secure_runtime.layout_version = STATE_MAP_SECURE_LAYOUT_VERSION;
    g_secure_runtime.last_counter = 0u;
    g_secure_runtime.reserved = 0u;
  }
}

// ============================================================ Runtime updates
// ====

void state_map_attest_state_set_lifecycle(uint32_t lifecycle) {
  g_attest_state.lifecycle_state = lifecycle;
}

void state_map_attest_state_set_protocol_flags(uint32_t flags) {
  g_attest_state.protocol_flags = flags;
}

void state_map_attest_state_set_security_flags(uint32_t flags) {
  g_attest_state.security_flags = flags;
}

ATTEST_PRIV_CODE void state_map_config_shadow_refresh_from_hw(void) {
  // Snapshot live HW register state into the config shadow. Called under IRQ
  // mask by the attestation engine for Profile 3 to avoid torn reads.
  g_config_shadow.supported_protocol_version = PROTOCOL_VERSION;
  g_config_shadow.supported_profile_mask = STATE_MAP_CFG_PROFILE_MASK;

  g_config_shadow.uart_baudrate = huart1.Init.BaudRate;
  g_config_shadow.uart_frame_cfg = state_map_pack_uart_frame_cfg();
  g_config_shadow.hash_cfg = state_map_pack_hash_cfg();
  g_config_shadow.platform_cfg = state_map_pack_platform_cfg();

  g_config_shadow.sysclk_hz = HAL_RCC_GetSysClockFreq();
  g_config_shadow.hclk_hz = HAL_RCC_GetHCLKFreq();
  g_config_shadow.flash_wait_states =
      (uint32_t)(FLASH->ACR & FLASH_ACR_LATENCY_Msk);
  g_config_shadow.flash_write_delay = (uint32_t)__HAL_FLASH_GET_PROGRAM_DELAY();
}

// ============================================================ Read-only access
// ===

const state_map_attest_state_t *state_map_get_attest_state(void) {
  return (const state_map_attest_state_t *)&g_attest_state;
}

const state_map_config_shadow_t *state_map_get_config_shadow(void) {
  return (const state_map_config_shadow_t *)&g_config_shadow;
}

// ============================================================ Secure counter
// =====

ATTEST_PRIV_CODE uint32_t state_map_secure_get_last_counter(void) {
  return g_secure_runtime.last_counter;
}

ATTEST_PRIV_CODE void state_map_secure_set_last_counter(uint32_t counter) {
  g_secure_runtime.last_counter = counter;
}

// ============================================================ Region accessors
// ===

ATTEST_PRIV_CODE bool
state_map_get_profile1_flash_region(state_map_region_t *region) {
  // Main attested flash: .isr_vector through .fini_array (application code +
  // constants).
  const uintptr_t start_addr = (uintptr_t)__attest_flash_start__;
  const uintptr_t end_addr = (uintptr_t)__attest_flash_end__;

  if (region == NULL) {
    return false;
  }

  if ((start_addr < STATE_MAP_FLASH_BASE_ADDR) || (end_addr <= start_addr)) {
    return false;
  }

  region->start = (const uint8_t *)start_addr;
  region->length = (size_t)(end_addr - start_addr);
  return true;
}

ATTEST_PRIV_CODE bool
state_map_get_profile1_flash_priv_region(state_map_region_t *region) {
  // Privileged flash: attestation code, K_AUTH, K_ATTEST (8 KB at FLASH_PRIV).
  const uintptr_t start_addr = (uintptr_t)__attest_flash_priv_start__;
  const uintptr_t end_addr = (uintptr_t)__attest_flash_priv_end__;

  if (region == NULL) {
    return false;
  }

  if ((start_addr < STATE_MAP_FLASH_BASE_ADDR) || (end_addr <= start_addr)) {
    return false;
  }

  region->start = (const uint8_t *)start_addr;
  region->length = (size_t)(end_addr - start_addr);
  return true;
}

ATTEST_PRIV_CODE bool
state_map_get_profile2_ram_region(state_map_region_t *region) {
  // The application-selected attested RAM manifest (.app_attested_ram).
  // Excludes parser state, HAL handles, heap, stack, and all privileged
  // overlays — those change at runtime and would produce a different digest
  // every time.
  const uintptr_t start_addr = (uintptr_t)__app_attested_ram_start__;
  const uintptr_t end_addr = (uintptr_t)__app_attested_ram_end__;

  if (region == NULL) {
    return false;
  }

  if ((start_addr < (uintptr_t)__app_ram_start__) || (end_addr <= start_addr) ||
      (end_addr > (uintptr_t)__app_ram_end__)) {
    return false;
  }

  region->start = (const uint8_t *)start_addr;
  region->length = (size_t)(end_addr - start_addr);
  return true;
}

ATTEST_PRIV_CODE bool
state_map_get_profile3_config_region(state_map_region_t *region) {
  // Config shadow (.attest_cfg in RAM_PRIV), refreshed from HW under IRQ mask
  // immediately before hashing (see attestation_compute_valid_state).
  const uintptr_t start_addr = (uintptr_t)__attest_cfg_start__;
  const uintptr_t end_addr = (uintptr_t)__attest_cfg_end__;

  if (region == NULL) {
    return false;
  }

  if ((start_addr < (uintptr_t)__attest_ram_priv_start__) ||
      (end_addr <= start_addr) ||
      (end_addr > (uintptr_t)__attest_ram_priv_limit__)) {
    return false;
  }

  region->start = (const uint8_t *)start_addr;
  region->length = (size_t)(end_addr - start_addr);
  return true;
}
