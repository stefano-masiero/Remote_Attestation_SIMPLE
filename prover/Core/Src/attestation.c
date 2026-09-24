// attestation.c — privileged attestation engine
//
// This is the security-critical core of the prover. Every function carries
// ATTEST_PRIV_CODE and runs inside the privileged flash region (FLASH_PRIV),
// which the MPU restricts to privileged-only access. Entry is gated by the
// SVC dispatch path (see stm32h5xx_it.c::SVC_Handler and
// main.c::app_attestation_svc_dispatch).
//
// Two symmetric keys live here as ATTEST_PRIV_RODATA:
//   g_kauth_key   — K_AUTH: authenticates protocol messages (request and
//   response MACs).
//                   Shared with the verifier (verifier/constants.py::KAUTH).
//   g_kattest_key — K_ATTEST: derives the valid-state value from measured
//   region digests.
//                   Present ONLY on the prover; the verifier stores an opaque
//                   expected_vs baseline instead (see report §3.2 / Figure 7).
//
// The main entry point, attestation_process_request(), runs the full pipeline:
//   1) verify request MAC under K_AUTH,
//   2) check profile support and counter freshness,
//   3) hash each profile-dependent region with SHA-256,
//   4) HMAC the concatenated digests under K_ATTEST → local_vs,
//   5) compare local_vs against expected_vs in constant time,
//   6) advance the secure counter (even on mismatch — see report §3.2),
//   7) build and MAC the response under K_AUTH.
//
// When ATTESTATION_BENCHMARK is enabled, DWT cycle counters are captured around
// each stage and embedded in the response timing block (report Table 1).

#include "attestation.h"
#include "byte_utils.h"
#include "crypto.h"
#include "main.h"
#include "privileged_sections.h"
#include "state_map.h"

#include <string.h>

// ---- Profile IDs (must match the verifier's --profile argument) ----
#define ATTESTATION_PROFILE_FLASH_ONLY 1u
#define ATTESTATION_PROFILE_FLASH_AND_RAM 2u
#define ATTESTATION_PROFILE_FLASH_RAM_CFG 3u

// ---- Authenticated-data sizes for MAC input reconstruction ----
#define ATTESTATION_REQ_AUTH_DATA_SIZE                                         \
  (1u + 1u + 4u + 1u + PROTOCOL_NONCE_SIZE + PROTOCOL_VS_SIZE)
#define ATTESTATION_RESP_AUTH_MIN_SIZE                                         \
  (1u + 1u + 4u + 1u + 1u + 1u + PROTOCOL_NONCE_SIZE)
#define ATTESTATION_RESP_AUTH_DBG_SIZE                                         \
  (ATTESTATION_RESP_AUTH_MIN_SIZE + PROTOCOL_VS_SIZE)
#define ATTESTATION_RESP_AUTH_TIMING_SIZE                                      \
  (ATTESTATION_RESP_AUTH_MIN_SIZE + PROTOCOL_TIMING_SIZE)
#define ATTESTATION_RESP_AUTH_FULL_SIZE                                        \
  (ATTESTATION_RESP_AUTH_MIN_SIZE + PROTOCOL_VS_SIZE + PROTOCOL_TIMING_SIZE)
#define ATTESTATION_MAX_REGIONS 4u

// ---- Cryptographic keys (privileged read-only flash) ----

// K_AUTH: protocol authentication (shared with the verifier).
ATTEST_PRIV_RODATA static const uint8_t g_kauth_key[32] = {
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u, 0x18u, 0x19u, 0x1Au,
    0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu, 0x20u, 0x21u, 0x22u, 0x23u, 0x24u, 0x25u,
    0x26u, 0x27u, 0x28u, 0x29u, 0x2Au, 0x2Bu, 0x2Cu, 0x2Du, 0x2Eu, 0x2Fu,
};

// K_ATTEST: valid-state derivation (prover-only, verifier never sees this key).
ATTEST_PRIV_RODATA static const uint8_t g_kattest_key[32] = {
    0xA0u, 0xA1u, 0xA2u, 0xA3u, 0xA4u, 0xA5u, 0xA6u, 0xA7u, 0xA8u, 0xA9u, 0xAAu,
    0xABu, 0xACu, 0xADu, 0xAEu, 0xAFu, 0xB0u, 0xB1u, 0xB2u, 0xB3u, 0xB4u, 0xB5u,
    0xB6u, 0xB7u, 0xB8u, 0xB9u, 0xBAu, 0xBBu, 0xBCu, 0xBDu, 0xBEu, 0xBFu,
};

// ============================================================ Benchmark
// helpers ==

void attestation_benchmark_init(void) {
#if (ATTESTATION_BENCHMARK == 1u)
  /* Enable the Cortex-M DWT cycle counter before entering unprivileged mode. */
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  DWT->CYCCNT = 0u;
  DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
#endif
}

ATTEST_PRIV_CODE static uint32_t attestation_benchmark_cycles_now(void) {
#if (ATTESTATION_BENCHMARK == 1u)
  return DWT->CYCCNT;
#else
  return 0u;
#endif
}

ATTEST_PRIV_CODE static uint32_t
attestation_benchmark_cycles_delta(uint32_t start) {
#if (ATTESTATION_BENCHMARK == 1u)
  return attestation_benchmark_cycles_now() - start;
#else
  (void)start;
  return 0u;
#endif
}

ATTEST_PRIV_CODE static void
attestation_benchmark_reset(protocol_attest_timing_t *timing) {
  if (timing != NULL) {
    memset(timing, 0, sizeof(*timing));
  }
}

// ============================================================ Serialization
// ======

ATTEST_PRIV_CODE static void
attestation_write_timing(uint8_t *buf, size_t *offset,
                         const protocol_attest_timing_t *timing) {
  write_u32_le(&buf[*offset], timing->req_mac_cycles);
  *offset += 4u;
  write_u32_le(&buf[*offset], timing->state_cycles);
  *offset += 4u;
  write_u32_le(&buf[*offset], timing->compare_cycles);
  *offset += 4u;
  write_u32_le(&buf[*offset], timing->response_mac_cycles);
  *offset += 4u;
  write_u32_le(&buf[*offset], timing->total_cycles);
  *offset += 4u;
}

ATTEST_PRIV_CODE static size_t
attestation_serialize_request_auth(const protocol_attest_req_t *req,
                                   uint8_t *buf, size_t buf_size) {
  // Build the exact byte sequence the request MAC is computed over (must match
  // the verifier's wire.build_req_auth). Includes version+type so a frame
  // cannot be replayed as a different message kind.
  size_t offset = 0u;

  if ((req == NULL) || (buf == NULL) ||
      (buf_size < ATTESTATION_REQ_AUTH_DATA_SIZE)) {
    return 0u;
  }

  buf[offset++] = PROTOCOL_VERSION;
  buf[offset++] = PROTOCOL_MSG_ATTEST_REQ;
  write_u32_le(&buf[offset], req->counter);
  offset += 4u;
  buf[offset++] = req->profile_id;
  memcpy(&buf[offset], req->nonce, PROTOCOL_NONCE_SIZE);
  offset += PROTOCOL_NONCE_SIZE;
  memcpy(&buf[offset], req->expected_vs, PROTOCOL_VS_SIZE);
  offset += PROTOCOL_VS_SIZE;

  return offset;
}

ATTEST_PRIV_CODE static size_t
attestation_serialize_response_auth(const protocol_attest_resp_t *resp,
                                    const uint8_t nonce[PROTOCOL_NONCE_SIZE],
                                    bool include_local_vs, uint8_t *buf,
                                    size_t buf_size) {
  // Build the exact byte sequence the response MAC is computed over. The nonce
  // (from the request) binds this response to the specific challenge.
  size_t offset = 0u;
  size_t required_size;
  uint8_t wire_flags;
  bool include_timing;

  if ((resp == NULL) || (nonce == NULL) || (buf == NULL)) {
    return 0u;
  }

  wire_flags =
      include_local_vs
          ? (resp->flags | PROTOCOL_RESP_FLAG_LOCAL_VS_PRESENT)
          : (resp->flags & (uint8_t)(~PROTOCOL_RESP_FLAG_LOCAL_VS_PRESENT));
  include_timing = ((wire_flags & PROTOCOL_RESP_FLAG_TIMING_PRESENT) != 0u);

  required_size = ATTESTATION_RESP_AUTH_MIN_SIZE;
  if (include_local_vs) {
    required_size += PROTOCOL_VS_SIZE;
  }
  if (include_timing) {
    required_size += PROTOCOL_TIMING_SIZE;
  }

  if (buf_size < required_size) {
    return 0u;
  }

  buf[offset++] = PROTOCOL_VERSION;
  buf[offset++] = PROTOCOL_MSG_ATTEST_RESP;
  write_u32_le(&buf[offset], resp->counter);
  offset += 4u;
  buf[offset++] = resp->profile_id;
  buf[offset++] = resp->result;
  buf[offset++] = wire_flags;

  memcpy(&buf[offset], nonce, PROTOCOL_NONCE_SIZE);
  offset += PROTOCOL_NONCE_SIZE;

  if (include_local_vs) {
    memcpy(&buf[offset], resp->local_vs, PROTOCOL_VS_SIZE);
    offset += PROTOCOL_VS_SIZE;
  }

  if (include_timing) {
    attestation_write_timing(buf, &offset, &resp->timing);
  }

  return offset;
}

// ============================================================ Response MAC
// =======

ATTEST_PRIV_CODE static attestation_status_t
attestation_finalize_response(protocol_attest_resp_t *resp,
                              const uint8_t nonce[PROTOCOL_NONCE_SIZE],
                              bool include_local_vs) {
  // Compute and embed the response MAC under K_AUTH. When benchmarking is
  // enabled, a preliminary pass measures the HMAC cost so the timing block is
  // self-consistent.
  uint8_t auth_data[ATTESTATION_RESP_AUTH_FULL_SIZE];
  size_t auth_len;
  crypto_status_t crypto_status;

#if (ATTESTATION_BENCHMARK == 1u)
  if ((resp != NULL) &&
      ((resp->flags & PROTOCOL_RESP_FLAG_TIMING_PRESENT) != 0u)) {
    uint32_t t_mac;

    // First pass: compute the HMAC to measure its cycle cost; the resulting MAC
    // is overwritten by the second (final) pass below, which includes the
    // now-known response_mac_cycles value in the authenticated data.
    resp->timing.response_mac_cycles = 0u;
    auth_len = attestation_serialize_response_auth(
        resp, nonce, include_local_vs, auth_data, sizeof(auth_data));
    if (auth_len == 0u) {
      return ATTESTATION_STATUS_INVALID_ARG;
    }

    t_mac = attestation_benchmark_cycles_now();
    crypto_status = crypto_hmac_sha256(g_kauth_key, sizeof(g_kauth_key),
                                       auth_data, auth_len, resp->auth_mac);
    resp->timing.response_mac_cycles =
        attestation_benchmark_cycles_delta(t_mac);
    resp->timing.total_cycles += resp->timing.response_mac_cycles;

    if (crypto_status != CRYPTO_STATUS_OK) {
      crypto_secure_zero(auth_data, sizeof(auth_data));
      return ATTESTATION_STATUS_CRYPTO_ERROR;
    }
  }
#endif

  // Final (or only) pass: compute the definitive response MAC.
  auth_len = attestation_serialize_response_auth(resp, nonce, include_local_vs,
                                                 auth_data, sizeof(auth_data));
  if (auth_len == 0u) {
    return ATTESTATION_STATUS_INVALID_ARG;
  }

  crypto_status = crypto_hmac_sha256(g_kauth_key, sizeof(g_kauth_key),
                                     auth_data, auth_len, resp->auth_mac);
  crypto_secure_zero(auth_data, sizeof(auth_data));

  if (crypto_status != CRYPTO_STATUS_OK) {
    return ATTESTATION_STATUS_CRYPTO_ERROR;
  }

  return ATTESTATION_STATUS_OK;
}

// ============================================================ Request MAC
// ========

ATTEST_PRIV_CODE static bool
attestation_verify_request_mac(const protocol_attest_req_t *req) {
  // Recompute the request MAC under K_AUTH and compare in constant time.
  uint8_t auth_data[ATTESTATION_REQ_AUTH_DATA_SIZE];
  uint8_t expected_mac[CRYPTO_SHA256_DIGEST_SIZE];
  size_t auth_len;
  bool match = false;

  auth_len =
      attestation_serialize_request_auth(req, auth_data, sizeof(auth_data));
  if (auth_len == 0u) {
    return false;
  }

  if (crypto_hmac_sha256(g_kauth_key, sizeof(g_kauth_key), auth_data, auth_len,
                         expected_mac) == CRYPTO_STATUS_OK) {
    match = crypto_consttime_equal(expected_mac, req->auth_mac,
                                   PROTOCOL_AUTH_MAC_SIZE);
  }

  crypto_secure_zero(auth_data, sizeof(auth_data));
  crypto_secure_zero(expected_mac, sizeof(expected_mac));
  return match;
}

// ============================================================ Profile mapping
// ====

ATTEST_PRIV_CODE static bool
attestation_is_supported_profile(uint8_t profile_id) {
  return (profile_id == ATTESTATION_PROFILE_FLASH_ONLY) ||
         (profile_id == ATTESTATION_PROFILE_FLASH_AND_RAM) ||
         (profile_id == ATTESTATION_PROFILE_FLASH_RAM_CFG);
}

ATTEST_PRIV_CODE static bool attestation_get_regions_for_profile(
    uint8_t profile_id, state_map_region_t regions[ATTESTATION_MAX_REGIONS],
    size_t *region_count) {
  // Map a profile ID to the set of memory regions that must be hashed.
  // Profile 1: main flash + privileged flash (2 regions).
  // Profile 2: + .app_attested_ram            (3 regions).
  // Profile 3: + .attest_cfg                  (4 regions).
  if ((regions == NULL) || (region_count == NULL)) {
    return false;
  }

  *region_count = 0u;

  if (!state_map_get_profile1_flash_region(&regions[0])) {
    return false;
  }

  if (!state_map_get_profile1_flash_priv_region(&regions[1])) {
    return false;
  }
  *region_count = 2u;

  if (profile_id == ATTESTATION_PROFILE_FLASH_ONLY) {
    return true;
  }

  if (!state_map_get_profile2_ram_region(&regions[2])) {
    return false;
  }
  *region_count = 3u;

  if (profile_id == ATTESTATION_PROFILE_FLASH_AND_RAM) {
    return true;
  }

  if (profile_id == ATTESTATION_PROFILE_FLASH_RAM_CFG) {
    if (!state_map_get_profile3_config_region(&regions[3])) {
      return false;
    }
    *region_count = 4u;
    return true;
  }

  return false;
}

// ============================================================ VS computation
// =====

ATTEST_PRIV_CODE static attestation_status_t
attestation_compute_valid_state(uint8_t profile_id,
                                uint8_t out_vs[PROTOCOL_VS_SIZE]) {
  // Compute the profile-dependent valid-state value:
  //   1) SHA-256 each region individually,
  //   2) concatenate profile_id || digest_0 || ... || digest_N,
  //   3) HMAC-SHA-256 under K_ATTEST → local_vs (32 bytes).
  state_map_region_t regions[ATTESTATION_MAX_REGIONS];
  uint8_t digests[ATTESTATION_MAX_REGIONS][CRYPTO_SHA256_DIGEST_SIZE];
  uint8_t vs_input[1u + (ATTESTATION_MAX_REGIONS * CRYPTO_SHA256_DIGEST_SIZE)];
  size_t region_count = 0u;
  size_t i;
  size_t vs_len;
  crypto_status_t crypto_status = CRYPTO_STATUS_HAL_ERROR;

  if (out_vs == NULL) {
    return ATTESTATION_STATUS_INVALID_ARG;
  }

  if (!attestation_get_regions_for_profile(profile_id, regions,
                                           &region_count)) {
    return ATTESTATION_STATUS_INVALID_ARG;
  }

  // Profile 3 includes the config shadow; snapshot it under IRQ mask to avoid
  // torn reads from HW registers that could change mid-hash.
  if (profile_id == ATTESTATION_PROFILE_FLASH_RAM_CFG) {
    uint32_t primask = __get_PRIMASK();
    __disable_irq();
    state_map_config_shadow_refresh_from_hw();
    __set_PRIMASK(primask);
  }

  for (i = 0u; i < region_count; i++) {
    crypto_status =
        crypto_sha256(regions[i].start, regions[i].length, digests[i]);
    if (crypto_status != CRYPTO_STATUS_OK) {
      break;
    }
  }

  if (crypto_status == CRYPTO_STATUS_OK) {
    vs_input[0] = profile_id;
    vs_len = 1u;

    for (i = 0u; i < region_count; i++) {
      memcpy(&vs_input[vs_len], digests[i], CRYPTO_SHA256_DIGEST_SIZE);
      vs_len += CRYPTO_SHA256_DIGEST_SIZE;
    }

    crypto_status = crypto_hmac_sha256(g_kattest_key, sizeof(g_kattest_key),
                                       vs_input, vs_len, out_vs);
  }

  // Wipe intermediate cryptographic material.
  crypto_secure_zero(digests, sizeof(digests));
  crypto_secure_zero(vs_input, sizeof(vs_input));

  if (crypto_status != CRYPTO_STATUS_OK) {
    return ATTESTATION_STATUS_CRYPTO_ERROR;
  }

  return ATTESTATION_STATUS_OK;
}

// ============================================================ Main entry point
// ===

ATTEST_PRIV_CODE attestation_status_t attestation_process_request(
    const protocol_attest_req_t *req, protocol_attest_resp_t *resp,
    bool *include_local_vs) {
  // Full attestation pipeline. See the module header for the step-by-step flow.
  attestation_status_t status;
  uint32_t stored_counter;
  uint32_t t_total = 0u;
  uint32_t t_op;
  bool mac_ok;
  bool vs_match;

  if ((req == NULL) || (resp == NULL) || (include_local_vs == NULL)) {
    return ATTESTATION_STATUS_INVALID_ARG;
  }

#if (ATTESTATION_BENCHMARK == 1u)
  t_total = attestation_benchmark_cycles_now();
#endif

  memset(resp, 0, sizeof(*resp));
  attestation_benchmark_reset(&resp->timing);
  resp->profile_id = req->profile_id;
  resp->flags = PROTOCOL_RESP_FLAG_NONE;
#if (ATTESTATION_BENCHMARK == 1u)
  resp->flags |= PROTOCOL_RESP_FLAG_TIMING_PRESENT;
#endif
  *include_local_vs = false;

  stored_counter = state_map_secure_get_last_counter();
  resp->counter = stored_counter;

  // ---- Step 1: verify request MAC ----
  t_op = attestation_benchmark_cycles_now();
  mac_ok = attestation_verify_request_mac(req);
  resp->timing.req_mac_cycles = attestation_benchmark_cycles_delta(t_op);
  if (!mac_ok) {
    resp->result = PROTOCOL_RESULT_AUTH_FAILURE;
    resp->timing.total_cycles = attestation_benchmark_cycles_delta(t_total);
    return attestation_finalize_response(resp, req->nonce, false);
  }

  // ---- Step 2: profile support ----
  if (!attestation_is_supported_profile(req->profile_id)) {
    resp->result = PROTOCOL_RESULT_UNSUPPORTED;
    resp->timing.total_cycles = attestation_benchmark_cycles_delta(t_total);
    return attestation_finalize_response(resp, req->nonce, false);
  }

  // ---- Step 3: counter freshness ----
  if (req->counter <= stored_counter) {
    resp->result = PROTOCOL_RESULT_STALE_COUNTER;
    resp->timing.total_cycles = attestation_benchmark_cycles_delta(t_total);
    return attestation_finalize_response(resp, req->nonce, false);
  }

  // ---- Step 4: compute local valid state ----
  t_op = attestation_benchmark_cycles_now();
  status = attestation_compute_valid_state(req->profile_id, resp->local_vs);
  resp->timing.state_cycles = attestation_benchmark_cycles_delta(t_op);
  if (status != ATTESTATION_STATUS_OK) {
    resp->result = PROTOCOL_RESULT_INTERNAL_ERROR;
    resp->timing.total_cycles = attestation_benchmark_cycles_delta(t_total);
    return attestation_finalize_response(resp, req->nonce, false);
  }

#if (ATTESTATION_INCLUDE_LOCAL_VS_DEBUG == 1u)
  *include_local_vs = true;
#endif

  // ---- Step 5: advance counter (even on mismatch — see report §3.2) ----
  state_map_secure_set_last_counter(req->counter);
  resp->counter = req->counter;

  // ---- Step 6: constant-time comparison ----
  t_op = attestation_benchmark_cycles_now();
  vs_match = crypto_consttime_equal(resp->local_vs, req->expected_vs,
                                    PROTOCOL_VS_SIZE);
  resp->timing.compare_cycles = attestation_benchmark_cycles_delta(t_op);
  if (vs_match) {
    resp->result = PROTOCOL_RESULT_SUCCESS;
  } else {
    resp->result = PROTOCOL_RESULT_ATTESTATION_FAILURE;
  }

  // ---- Step 7: build and MAC the response ----
  resp->timing.total_cycles = attestation_benchmark_cycles_delta(t_total);
  return attestation_finalize_response(resp, req->nonce, *include_local_vs);
}
