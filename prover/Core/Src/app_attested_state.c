// app_attested_state.c — application-defined manifest placed in
// .app_attested_ram
//
// This small structure is the ONLY part of application RAM that is measured by
// Profiles 2 and 3 (see report §2.6 / Figure 5). It is initialised from flash
// at startup, so its digest tracks the flashed binary and remains stable across
// runs — unlike heap, stack, HAL handles, and parser buffers, which are
// excluded.
//
// The manifest declares what the firmware supports (protocol version, profile
// mask) so the verifier can detect a mismatch if the deployed binary diverges
// from the enrolled baseline.

#include <stdint.h>

#include "protocol.h"

#define APP_ATTESTED_RAM_MAGIC 0x4152414Du /* "ARAM" */
#define APP_ATTESTED_RAM_VERSION 0x00000001u
#define APP_ATTESTED_PROFILE_MASK 0x00000007u /* profiles 1, 2, 3 */

typedef struct {
  uint32_t magic;
  uint32_t version;
  uint32_t protocol_version;
  uint32_t supported_profile_mask;
  uint32_t reserved[4];
} app_attested_ram_manifest_t;

// Placed in the .app_attested_ram section by the linker script; the section
// lives inside the application-visible RAM window but is measured separately
// from .bss.
volatile app_attested_ram_manifest_t g_app_attested_ram_manifest
    __attribute__((section(".app_attested_ram"), aligned(4), used)) = {
        .magic = APP_ATTESTED_RAM_MAGIC,
        .version = APP_ATTESTED_RAM_VERSION,
        .protocol_version = PROTOCOL_VERSION,
        .supported_profile_mask = APP_ATTESTED_PROFILE_MASK,
        .reserved = {0u, 0u, 0u, 0u},
};
