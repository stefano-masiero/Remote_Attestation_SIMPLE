// protocol.h — wire-protocol constants, types, parser and frame builder (prover
// side)
//
// Defines the custom binary framing shared with the verifier (see report §2.4):
//
//   frame = SOF0 SOF1 | version(1) | msg_type(1) | payload_len(u16 LE) |
//   payload | CRC16(u16 LE)
//
// The CRC is CRC-16/CCITT-FALSE (init 0xFFFF, poly 0x1021, no reflection) for
// accidental-corruption detection only — end-to-end integrity comes from HMAC.
//
// Payload layouts (matching verifier/constants.py and report Figure 4):
//   request  = counter(4) profile_id(1) nonce(16) expected_vs(32) auth_mac(32)
//   = 85 B response = counter(4) profile_id(1) result(1) flags(1)
//   [local_vs(32)] [timing(20)] auth_mac(32)
//
// The byte-by-byte parser (protocol_parser_consume_byte) is driven from the
// main loop's UART polling; it emits PROTOCOL_PARSE_FRAME_READY when a
// complete, CRC-valid frame has been assembled.

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---- Framing constants ----
#define PROTOCOL_SOF_0 0xA5u
#define PROTOCOL_SOF_1 0x5Au
#define PROTOCOL_VERSION 0x01u

#define PROTOCOL_MAX_PAYLOAD_SIZE 128u
#define PROTOCOL_FRAME_OVERHEAD                                                \
  8u // SOF(2) + ver(1) + type(1) + len(2) + CRC(2)
#define PROTOCOL_MAX_FRAME_SIZE                                                \
  (PROTOCOL_MAX_PAYLOAD_SIZE + PROTOCOL_FRAME_OVERHEAD)

// ---- Field sizes (bytes) ----
#define PROTOCOL_NONCE_SIZE 16u
#define PROTOCOL_VS_SIZE 32u
#define PROTOCOL_AUTH_MAC_SIZE 32u
#define PROTOCOL_TIMING_FIELD_COUNT                                            \
  5u // req_mac, state, compare, resp_mac, total
#define PROTOCOL_TIMING_SIZE (PROTOCOL_TIMING_FIELD_COUNT * 4u)

// ---- Derived payload sizes ----
#define PROTOCOL_REQ_PAYLOAD_SIZE                                              \
  (4u + 1u + PROTOCOL_NONCE_SIZE + PROTOCOL_VS_SIZE + PROTOCOL_AUTH_MAC_SIZE)
#define PROTOCOL_RESP_PAYLOAD_MIN_SIZE                                         \
  (4u + 1u + 1u + 1u + PROTOCOL_AUTH_MAC_SIZE)
#define PROTOCOL_RESP_PAYLOAD_DBG_SIZE                                         \
  (PROTOCOL_RESP_PAYLOAD_MIN_SIZE + PROTOCOL_VS_SIZE)
#define PROTOCOL_RESP_PAYLOAD_TIMING_SIZE                                      \
  (PROTOCOL_RESP_PAYLOAD_MIN_SIZE + PROTOCOL_TIMING_SIZE)
#define PROTOCOL_RESP_PAYLOAD_FULL_SIZE                                        \
  (PROTOCOL_RESP_PAYLOAD_MIN_SIZE + PROTOCOL_VS_SIZE + PROTOCOL_TIMING_SIZE)

// ---- Message types ----
typedef enum {
  PROTOCOL_MSG_ATTEST_REQ = 0x01u,
  PROTOCOL_MSG_ATTEST_RESP = 0x02u,
} protocol_msg_type_t;

// ---- Response flag bits ----
typedef enum {
  PROTOCOL_RESP_FLAG_NONE = 0x00u,
  PROTOCOL_RESP_FLAG_LOCAL_VS_PRESENT =
      0x01u, // response carries the prover-computed local_vs
  PROTOCOL_RESP_FLAG_TIMING_PRESENT =
      0x02u, // response carries the prover-side timing block
} protocol_resp_flags_t;

// ---- Attestation result codes ----
typedef enum {
  PROTOCOL_RESULT_SUCCESS = 0x00u,
  PROTOCOL_RESULT_BAD_REQUEST = 0xE1u,
  PROTOCOL_RESULT_UNSUPPORTED = 0xE2u,
  PROTOCOL_RESULT_AUTH_FAILURE = 0xE3u,        // request MAC mismatch
  PROTOCOL_RESULT_ATTESTATION_FAILURE = 0xE4u, // measured state != expected_vs
  PROTOCOL_RESULT_INTERNAL_ERROR = 0xE5u,
  PROTOCOL_RESULT_STALE_COUNTER = 0xE6u, // replay protection
  PROTOCOL_RESULT_NOT_IMPLEMENTED = 0xEEu,
} protocol_result_t;

// ---- API status codes ----
typedef enum {
  PROTOCOL_STATUS_OK = 0,
  PROTOCOL_STATUS_INVALID_ARG,
  PROTOCOL_STATUS_UNSUPPORTED_VERSION,
  PROTOCOL_STATUS_UNSUPPORTED_TYPE,
  PROTOCOL_STATUS_BAD_LENGTH,
  PROTOCOL_STATUS_BAD_CRC,
  PROTOCOL_STATUS_BUFFER_TOO_SMALL,
} protocol_status_t;

// ---- Parser return values ----
typedef enum {
  PROTOCOL_PARSE_NEED_MORE = 0, // feed more bytes
  PROTOCOL_PARSE_FRAME_READY,   // complete frame assembled
  PROTOCOL_PARSE_ERROR,         // CRC mismatch or framing error
} protocol_parse_status_t;

// ---- On-wire frame (assembled by the parser or by protocol_build_frame) ----
typedef struct {
  uint8_t version;
  uint8_t msg_type;
  uint16_t payload_len;
  uint8_t payload[PROTOCOL_MAX_PAYLOAD_SIZE];
  uint16_t crc16;
} protocol_frame_t;

// ---- Byte-by-byte parser state machine ----
typedef enum {
  PROTOCOL_PSTATE_WAIT_SOF0 = 0,
  PROTOCOL_PSTATE_WAIT_SOF1,
  PROTOCOL_PSTATE_VERSION,
  PROTOCOL_PSTATE_TYPE,
  PROTOCOL_PSTATE_LEN0,
  PROTOCOL_PSTATE_LEN1,
  PROTOCOL_PSTATE_PAYLOAD,
  PROTOCOL_PSTATE_CRC0,
  PROTOCOL_PSTATE_CRC1,
} protocol_parser_state_t;

typedef struct {
  protocol_parser_state_t state;
  protocol_frame_t frame;
  uint16_t payload_index;
  uint16_t crc_index;
  uint8_t crc_bytes[2];
} protocol_parser_t;

// ---- Typed attestation request / response payloads ----
typedef struct {
  uint32_t counter;
  uint8_t profile_id;
  uint8_t nonce[PROTOCOL_NONCE_SIZE];
  uint8_t expected_vs[PROTOCOL_VS_SIZE];
  uint8_t auth_mac[PROTOCOL_AUTH_MAC_SIZE];
} protocol_attest_req_t;

// Prover-side cycle counters (optional timing block, report Table 1).
typedef struct {
  uint32_t req_mac_cycles;
  uint32_t state_cycles;
  uint32_t compare_cycles;
  uint32_t response_mac_cycles;
  uint32_t total_cycles;
} protocol_attest_timing_t;

typedef struct {
  uint32_t counter;
  uint8_t profile_id;
  uint8_t result;
  uint8_t flags;
  uint8_t local_vs[PROTOCOL_VS_SIZE];
  protocol_attest_timing_t timing;
  uint8_t auth_mac[PROTOCOL_AUTH_MAC_SIZE];
} protocol_attest_resp_t;

// ---- Parser API ----
void protocol_parser_init(protocol_parser_t *parser);
void protocol_parser_reset(protocol_parser_t *parser);
protocol_parse_status_t
protocol_parser_consume_byte(protocol_parser_t *parser, uint8_t byte,
                             protocol_frame_t *out_frame);

// ---- Frame building / parsing ----
protocol_status_t protocol_build_frame(const protocol_frame_t *frame,
                                       uint8_t *out_buf, size_t out_buf_size,
                                       size_t *out_len);

protocol_status_t protocol_parse_attest_req(const protocol_frame_t *frame,
                                            protocol_attest_req_t *req);

protocol_status_t
protocol_build_attest_resp_frame(const protocol_attest_resp_t *resp,
                                 bool include_local_vs,
                                 protocol_frame_t *frame);

// CRC-16/CCITT-FALSE (accidental-corruption detection, not a security
// mechanism).
uint16_t protocol_crc16_ccitt(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_H */
