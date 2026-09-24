// crypto.c — hardware-accelerated SHA-256/HMAC-SHA256 and security helpers
//
// All functions carry ATTEST_PRIV_CODE so they execute inside the privileged
// flash region. The HASH peripheral is GTZC-protected (see MX_GTZC_Init in
// main.c), so only privileged code can drive it — unprivileged firmware cannot
// forge digests.
//
// The peripheral is re-initialised before every operation
// (crypto_reconfigure_hash) because the attestation engine switches between
// plain SHA-256 (region hashing) and HMAC-SHA-256 (K_ATTEST derivation, K_AUTH
// authentication) within a single request.
//
// crypto_consttime_equal() and crypto_secure_zero() are not
// performance-critical but are security-critical: one prevents timing-based
// side channels on the VS comparison, the other prevents key material from
// lingering in the mailbox after a transaction.

#include "crypto.h"

#include "main.h"
#include "privileged_sections.h"
#include <string.h>

extern HASH_HandleTypeDef hhash;

#define CRYPTO_HASH_TIMEOUT_MS 5000u

// ============================================================ HASH reconfigure
// ==

ATTEST_PRIV_CODE static crypto_status_t
crypto_reconfigure_hash(const uint8_t *key, size_t key_len) {
  // DeInit + ReInit the HASH peripheral so it picks up the new algorithm/key.
  // Passing key=NULL / key_len=0 selects plain SHA-256; a non-NULL key selects
  // HMAC.
  HAL_StatusTypeDef hal_status;

  (void)HAL_HASH_DeInit(&hhash);

  hhash.Instance = HASH;
  hhash.Init.DataType = HASH_BYTE_SWAP;
  hhash.Init.Algorithm = HASH_ALGOSELECTION_SHA256;
  hhash.Init.pKey = (uint8_t *)key;
  hhash.Init.KeySize = (uint32_t)key_len;

  hal_status = HAL_HASH_Init(&hhash);
  if (hal_status != HAL_OK) {
    return CRYPTO_STATUS_HAL_ERROR;
  }

  return CRYPTO_STATUS_OK;
}

// ============================================================ SHA-256
// ===========

ATTEST_PRIV_CODE crypto_status_t
crypto_sha256(const uint8_t *data, size_t data_len,
              uint8_t out_digest[CRYPTO_SHA256_DIGEST_SIZE]) {
  if ((data == NULL) || (out_digest == NULL) || (data_len == 0u)) {
    return CRYPTO_STATUS_INVALID_ARG;
  }

  if (crypto_reconfigure_hash(NULL, 0u) != CRYPTO_STATUS_OK) {
    return CRYPTO_STATUS_HAL_ERROR;
  }

  if (HAL_HASH_Start(&hhash, data, (uint32_t)data_len, out_digest,
                     CRYPTO_HASH_TIMEOUT_MS) != HAL_OK) {
    return CRYPTO_STATUS_HAL_ERROR;
  }

  return CRYPTO_STATUS_OK;
}

// ============================================================ HMAC-SHA-256
// =======

ATTEST_PRIV_CODE crypto_status_t crypto_hmac_sha256(
    const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
    uint8_t out_mac[CRYPTO_SHA256_DIGEST_SIZE]) {
  if ((key == NULL) || (key_len == 0u) || (data == NULL) || (out_mac == NULL) ||
      (data_len == 0u)) {
    return CRYPTO_STATUS_INVALID_ARG;
  }

  if (crypto_reconfigure_hash(key, key_len) != CRYPTO_STATUS_OK) {
    return CRYPTO_STATUS_HAL_ERROR;
  }

  if (HAL_HASH_HMAC_Start(&hhash, data, (uint32_t)data_len, out_mac,
                          CRYPTO_HASH_TIMEOUT_MS) != HAL_OK) {
    return CRYPTO_STATUS_HAL_ERROR;
  }

  return CRYPTO_STATUS_OK;
}

// ============================================================ Security helpers
// ===

ATTEST_PRIV_CODE bool crypto_consttime_equal(const uint8_t *lhs,
                                             const uint8_t *rhs, size_t len) {
  // OR-accumulate all byte differences; any nonzero diff makes the final result
  // false. The loop always runs to completion regardless of where a mismatch
  // occurs.
  size_t i;
  uint8_t diff = 0u;

  if ((lhs == NULL) || (rhs == NULL)) {
    return false;
  }

  for (i = 0u; i < len; ++i) {
    diff |= (uint8_t)(lhs[i] ^ rhs[i]);
  }

  return (diff == 0u);
}

ATTEST_PRIV_CODE void crypto_secure_zero(void *buf, size_t len) {
  // Volatile pointer prevents the compiler from optimising away the stores.
  volatile uint8_t *p = (volatile uint8_t *)buf;
  size_t i;

  if (buf == NULL) {
    return;
  }

  for (i = 0u; i < len; ++i) {
    p[i] = 0u;
  }
}
