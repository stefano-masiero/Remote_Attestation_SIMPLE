// byte_utils.h — portable little-endian read/write helpers
//
// Used by both the protocol parser (protocol.c) and the attestation engine
// (attestation.c) to serialize/deserialize multi-byte wire fields without
// relying on struct packing or alignment assumptions.

#ifndef BYTE_UTILS_H
#define BYTE_UTILS_H

#include <stdint.h>

static inline uint16_t read_u16_le(const uint8_t *buf) {
  return (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
}

static inline uint32_t read_u32_le(const uint8_t *buf) {
  return ((uint32_t)buf[0]) | ((uint32_t)buf[1] << 8) |
         ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
}

static inline void write_u16_le(uint8_t *buf, uint16_t value) {
  buf[0] = (uint8_t)(value & 0xFFu);
  buf[1] = (uint8_t)((value >> 8) & 0xFFu);
}

static inline void write_u32_le(uint8_t *buf, uint32_t value) {
  buf[0] = (uint8_t)(value & 0xFFu);
  buf[1] = (uint8_t)((value >> 8) & 0xFFu);
  buf[2] = (uint8_t)((value >> 16) & 0xFFu);
  buf[3] = (uint8_t)((value >> 24) & 0xFFu);
}

#endif
