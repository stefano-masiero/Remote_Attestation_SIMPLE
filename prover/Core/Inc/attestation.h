// attestation.h — public interface of the privileged attestation engine
//
// The attestation engine is the security-critical core of the prover. It runs
// entirely in privileged flash (ATTEST_PRIV_CODE) and is entered only through
// the SVC dispatch path (see report §2.7 / §3.2 and main.c::SVC_Handler).
//
// The single entry point, attestation_process_request(), performs the full
// challenge-response pipeline inside the privileged context:
//   1) verify the request MAC under K_AUTH,
//   2) check profile support and counter freshness,
//   3) compute the profile-dependent valid state under K_ATTEST,
//   4) compare it against expected_vs in constant time,
//   5) build and MAC the response.
//
// Compile-time knobs:
//   ATTESTATION_INCLUDE_LOCAL_VS_DEBUG — include local_vs in responses
//   (debug/bootstrap). ATTESTATION_BENCHMARK             — enable DWT
//   cycle-counter instrumentation for the
//                                       prover-side timing block (Table 1 in
//                                       the report).

#ifndef ATTESTATION_H
#define ATTESTATION_H

#include <stdbool.h>

#include "protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

// Set to 1u to include the prover-computed local_vs in every response.
// Useful for bootstrap and testing; should be 0u in a hardened deployment.
#define ATTESTATION_INCLUDE_LOCAL_VS_DEBUG 1u

// Set to 1u to enable Cortex-M cycle-counter timing and include the timing
// block in responses. Set to 0u for production builds.
#define ATTESTATION_BENCHMARK 1u

typedef enum {
  ATTESTATION_STATUS_OK = 0,
  ATTESTATION_STATUS_INVALID_ARG,
  ATTESTATION_STATUS_CRYPTO_ERROR,
} attestation_status_t;

// Enable the DWT cycle counter (called once from main before entering
// unprivileged mode).
void attestation_benchmark_init(void);

// Full attestation pipeline. Runs in privileged context via the SVC mailbox.
// On return, resp is fully populated (including the response MAC) and
// *include_local_vs indicates whether the response carries local_vs.
attestation_status_t
attestation_process_request(const protocol_attest_req_t *req,
                            protocol_attest_resp_t *resp,
                            bool *include_local_vs);

#ifdef __cplusplus
}
#endif

#endif /* ATTESTATION_H */
