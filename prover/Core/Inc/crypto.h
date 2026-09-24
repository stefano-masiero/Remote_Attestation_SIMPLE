// crypto.h — hardware-accelerated cryptographic primitives for the prover
//
// Thin wrappers around the STM32 HASH peripheral that provide the two
// operations the attestation engine needs:
//   - crypto_sha256()       : plain SHA-256, used to hash each measured memory
//   region.
//   - crypto_hmac_sha256()  : HMAC-SHA256, used both for valid-state derivation
//                             (under K_ATTEST) and for protocol authentication
//                             (under K_AUTH).
//
// All functions run inside the privileged flash region (ATTEST_PRIV_CODE) so
// they can access the HASH peripheral, which is GTZC-protected as
// privileged-only.
//
// Also provides:
//   - crypto_consttime_equal() : constant-time buffer comparison (avoids timing
//   leaks
//                                when comparing expected_vs against local_vs).
//   - crypto_secure_zero()     : volatile-qualified zeroization that the
//   compiler cannot
//                                optimize away (used to wipe key material and
//                                intermediate buffers after every transaction).

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPTO_SHA256_DIGEST_SIZE 32u

typedef enum {
  CRYPTO_STATUS_OK = 0,
  CRYPTO_STATUS_INVALID_ARG,
  CRYPTO_STATUS_HAL_ERROR,
} crypto_status_t;

// Compute SHA-256 over a contiguous buffer using the HASH peripheral.
crypto_status_t crypto_sha256(const uint8_t *data, size_t data_len,
                              uint8_t out_digest[CRYPTO_SHA256_DIGEST_SIZE]);

// Compute HMAC-SHA-256 over a contiguous buffer using the HASH peripheral.
crypto_status_t crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                                   const uint8_t *data, size_t data_len,
                                   uint8_t out_mac[CRYPTO_SHA256_DIGEST_SIZE]);

// Constant-time comparison of two buffers (returns true iff identical).
bool crypto_consttime_equal(const uint8_t *lhs, const uint8_t *rhs, size_t len);

// Volatile zeroization that cannot be dead-store-eliminated.
void crypto_secure_zero(void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_H */
