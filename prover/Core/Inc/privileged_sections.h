// privileged_sections.h — GCC section-placement macros for the privilege
// boundary
//
// These macros direct the linker to place attestation code, read-only data, and
// the privileged mailbox into the custom sections defined in
// STM32H503xx_FLASH.ld:
//
//   ATTEST_PRIV_CODE   → .flash_priv_text   (FLASH_PRIV region, privileged-only
//   via MPU) ATTEST_PRIV_RODATA → .flash_priv_rodata (same region; holds K_AUTH
//   and K_ATTEST) ATTEST_PRIV_DATA   → .attest_mailbox    (RAM_PRIV region; the
//   SVC request/response buffer)
//
// Because the MPU marks these regions as privileged-only (see MPU_Config in
// main.c), unprivileged Thread mode cannot read, write, or execute them. The
// only entry point is the `svc 0` instruction, which raises SVCall and
// transfers control to the SVC_Handler running in privileged Handler mode (see
// report §2.7 and §3.2).

#ifndef PRIVILEGED_SECTIONS_H
#define PRIVILEGED_SECTIONS_H

#if defined(__GNUC__)
#define ATTEST_PRIV_CODE __attribute__((section(".flash_priv_text"), noinline))
#define ATTEST_PRIV_RODATA                                                     \
  __attribute__((section(".flash_priv_rodata"), aligned(32), used))
#define ATTEST_PRIV_DATA                                                       \
  __attribute__((section(".attest_mailbox"), aligned(4), used))
#else
#define ATTEST_PRIV_CODE
#define ATTEST_PRIV_RODATA
#define ATTEST_PRIV_DATA
#endif

#endif /* PRIVILEGED_SECTIONS_H */
