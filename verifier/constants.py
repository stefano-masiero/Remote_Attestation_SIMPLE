"""verifier.constants — wire-protocol constants shared by the verifier codebase.

These values define the custom binary framing and payload layout used between the
verifier and the STM32 prover (relayed transparently by the ESP32 gateway):

  frame = SOF0 SOF1 | version | msg_type | payload_len (u16 LE) | payload | CRC16 (u16 LE)

The payload layouts mirror the request/response figure in the report:
  request  = counter(4) profile_id(1) nonce(16) expected_vs(32) auth_mac(32)
  response = counter(4) profile_id(1) result(1) flags(1) [local_vs(32)] [timing(20)] auth_mac(32)

Only K_AUTH lives here, because in this prototype the verifier authenticates the
protocol exchange (request/response MAC) but does NOT recompute the valid state:
K_ATTEST is embedded only in the prover firmware. The verifier instead compares
the prover's local_vs against an enrolled expected_vs baseline.
"""

from __future__ import annotations

# ---- Framing ----
SOF0 = 0xA5  # start-of-frame byte 0
SOF1 = 0x5A  # start-of-frame byte 1
VERSION = 0x01  # protocol version
MSG_ATTEST_REQ = 0x01  # message type: attestation request  (verifier -> prover)
MSG_ATTEST_RESP = 0x02  # message type: attestation response (prover  -> verifier)

# ---- Field sizes (bytes) ----
NONCE_SIZE = 16
VS_SIZE = 32
AUTH_MAC_SIZE = 32  # HMAC-SHA256 tag length
TIMING_FIELD_COUNT = 5  # req_mac, state, compare, resp_mac, total
TIMING_SIZE = TIMING_FIELD_COUNT * 4  # 5 x uint32 LE

# ---- Derived payload sizes ----
REQ_PAYLOAD_SIZE = 4 + 1 + NONCE_SIZE + VS_SIZE + AUTH_MAC_SIZE
RESP_PAYLOAD_MIN_SIZE = (
    4 + 1 + 1 + 1 + AUTH_MAC_SIZE
)  # counter+profile+result+flags+mac
RESP_PAYLOAD_DBG_SIZE = RESP_PAYLOAD_MIN_SIZE + VS_SIZE  # + local_vs (debug build)
RESP_PAYLOAD_TIMING_SIZE = RESP_PAYLOAD_MIN_SIZE + TIMING_SIZE  # + timing block
RESP_PAYLOAD_FULL_SIZE = RESP_PAYLOAD_MIN_SIZE + VS_SIZE + TIMING_SIZE  # + both

# ---- Result codes (response `result` byte) ----
RESULT_SUCCESS = 0x00
RESULT_BAD_REQUEST = 0xE1
RESULT_UNSUPPORTED = 0xE2
RESULT_AUTH_FAILURE = 0xE3
RESULT_ATTESTATION_FAILURE = (
    0xE4  # well-formed request, but measured state != expected_vs
)
RESULT_INTERNAL_ERROR = 0xE5
RESULT_STALE_COUNTER = (
    0xE6  # replay protection: counter not strictly greater than stored
)

# ---- Response flag bits (`flags` byte) ----
FLAG_LOCAL_VS_PRESENT = (
    0x01  # response carries the prover-computed local_vs (debug build)
)
FLAG_TIMING_PRESENT = 0x02  # response carries the prover-side timing block

# Protocol-authentication key, shared by verifier and prover. Used ONLY for the
# request/response HMAC (end-to-end integrity + source authenticity). This is the
# K_AUTH of the report; K_ATTEST (used by the prover to derive the VS) is intentionally
# absent here. Static embedding is a prototype simplification, not production-grade.
KAUTH = bytes(
    [
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
        0x19,
        0x1A,
        0x1B,
        0x1C,
        0x1D,
        0x1E,
        0x1F,
        0x20,
        0x21,
        0x22,
        0x23,
        0x24,
        0x25,
        0x26,
        0x27,
        0x28,
        0x29,
        0x2A,
        0x2B,
        0x2C,
        0x2D,
        0x2E,
        0x2F,
    ]
)

# Human-readable profile labels; index = measured-region scope (see report Figure 5).
PROFILE_NAMES = {
    1: "flash-only",
    2: "flash+ram",
    3: "flash+ram+cfg",
}

# Reverse lookup from result byte to a printable name.
RESULT_NAMES = {
    RESULT_SUCCESS: "SUCCESS",
    RESULT_BAD_REQUEST: "BAD_REQUEST",
    RESULT_UNSUPPORTED: "UNSUPPORTED",
    RESULT_AUTH_FAILURE: "AUTH_FAILURE",
    RESULT_ATTESTATION_FAILURE: "ATTESTATION_FAILURE",
    RESULT_INTERNAL_ERROR: "INTERNAL_ERROR",
    RESULT_STALE_COUNTER: "STALE_COUNTER",
}
