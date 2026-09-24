// protocol.c — wire-protocol framing, CRC-16, byte parser and payload builders
//
// This module handles everything between raw UART bytes and typed attestation
// structures. It runs in unprivileged application flash (not ATTEST_PRIV_CODE)
// because it touches only public protocol data, never keys or secure state.
//
// The byte-by-byte parser (protocol_parser_consume_byte) is designed for the
// prover's polling main loop: each received UART byte is fed in, and when a
// complete CRC-valid frame has been assembled the parser emits FRAME_READY.
//
// On the TX side, protocol_build_attest_resp_frame() packs a typed response
// into a protocol_frame_t, and protocol_build_frame() serializes it with SOF,
// header, payload and CRC trailer ready for HAL_UART_Transmit.

#include "protocol.h"

#include "byte_utils.h"
#include <string.h>

// ---- Timing serialization (shared with attestation.c) ----

static void protocol_write_timing(uint8_t *payload, size_t *offset,
                                  const protocol_attest_timing_t *timing) {
  write_u32_le(&payload[*offset], timing->req_mac_cycles);
  *offset += 4u;
  write_u32_le(&payload[*offset], timing->state_cycles);
  *offset += 4u;
  write_u32_le(&payload[*offset], timing->compare_cycles);
  *offset += 4u;
  write_u32_le(&payload[*offset], timing->response_mac_cycles);
  *offset += 4u;
  write_u32_le(&payload[*offset], timing->total_cycles);
  *offset += 4u;
}

// ============================================================ Frame validation
// ==

static protocol_status_t validate_frame_header(const protocol_frame_t *frame) {
  if (frame == NULL) {
    return PROTOCOL_STATUS_INVALID_ARG;
  }

  if (frame->version != PROTOCOL_VERSION) {
    return PROTOCOL_STATUS_UNSUPPORTED_VERSION;
  }

  if ((frame->msg_type != PROTOCOL_MSG_ATTEST_REQ) &&
      (frame->msg_type != PROTOCOL_MSG_ATTEST_RESP)) {
    return PROTOCOL_STATUS_UNSUPPORTED_TYPE;
  }

  if (frame->payload_len > PROTOCOL_MAX_PAYLOAD_SIZE) {
    return PROTOCOL_STATUS_BAD_LENGTH;
  }

  return PROTOCOL_STATUS_OK;
}

// ============================================================ CRC-16
// ============

uint16_t protocol_crc16_ccitt(const uint8_t *data, size_t len) {
  // CRC-16/CCITT-FALSE: init 0xFFFF, poly 0x1021, no reflection, no final XOR.
  // Covers header + payload (not the SOF bytes). Used for accidental corruption
  // detection on the UART link; not a security mechanism.
  uint16_t crc = 0xFFFFu;
  size_t i;

  if (data == NULL) {
    return 0u;
  }

  for (i = 0; i < len; ++i) {
    uint8_t bit;

    crc ^= ((uint16_t)data[i] << 8);
    for (bit = 0; bit < 8u; ++bit) {
      if ((crc & 0x8000u) != 0u) {
        crc = (uint16_t)((crc << 1) ^ 0x1021u);
      } else {
        crc <<= 1;
      }
    }
  }

  return crc;
}

// ============================================================ Parser
// =============

void protocol_parser_init(protocol_parser_t *parser) {
  if (parser == NULL) {
    return;
  }

  memset(parser, 0, sizeof(*parser));
  parser->state = PROTOCOL_PSTATE_WAIT_SOF0;
}

void protocol_parser_reset(protocol_parser_t *parser) {
  protocol_parser_init(parser);
}

protocol_parse_status_t
protocol_parser_consume_byte(protocol_parser_t *parser, uint8_t byte,
                             protocol_frame_t *out_frame) {
  // State machine that assembles one frame from a stream of bytes. On CRC match
  // the completed frame is copied to *out_frame and FRAME_READY is returned.
  uint8_t crc_input[4 + PROTOCOL_MAX_PAYLOAD_SIZE];
  uint16_t computed_crc;
  uint16_t received_crc;

  if ((parser == NULL) || (out_frame == NULL)) {
    return PROTOCOL_PARSE_ERROR;
  }

  switch (parser->state) {
  case PROTOCOL_PSTATE_WAIT_SOF0:
    if (byte == PROTOCOL_SOF_0) {
      protocol_parser_reset(parser);
      parser->state = PROTOCOL_PSTATE_WAIT_SOF1;
    }
    return PROTOCOL_PARSE_NEED_MORE;

  case PROTOCOL_PSTATE_WAIT_SOF1:
    if (byte == PROTOCOL_SOF_1) {
      parser->state = PROTOCOL_PSTATE_VERSION;
    } else if (byte == PROTOCOL_SOF_0) {
      parser->state = PROTOCOL_PSTATE_WAIT_SOF1;
    } else {
      protocol_parser_reset(parser);
    }
    return PROTOCOL_PARSE_NEED_MORE;

  case PROTOCOL_PSTATE_VERSION:
    parser->frame.version = byte;
    parser->state = PROTOCOL_PSTATE_TYPE;
    return PROTOCOL_PARSE_NEED_MORE;

  case PROTOCOL_PSTATE_TYPE:
    parser->frame.msg_type = byte;
    parser->state = PROTOCOL_PSTATE_LEN0;
    return PROTOCOL_PARSE_NEED_MORE;

  case PROTOCOL_PSTATE_LEN0:
    parser->frame.payload_len = byte;
    parser->state = PROTOCOL_PSTATE_LEN1;
    return PROTOCOL_PARSE_NEED_MORE;

  case PROTOCOL_PSTATE_LEN1:
    parser->frame.payload_len |= (uint16_t)((uint16_t)byte << 8);
    parser->payload_index = 0u;

    if (parser->frame.payload_len > PROTOCOL_MAX_PAYLOAD_SIZE) {
      protocol_parser_reset(parser);
      return PROTOCOL_PARSE_ERROR;
    }

    if (parser->frame.payload_len == 0u) {
      parser->state = PROTOCOL_PSTATE_CRC0;
    } else {
      parser->state = PROTOCOL_PSTATE_PAYLOAD;
    }
    return PROTOCOL_PARSE_NEED_MORE;

  case PROTOCOL_PSTATE_PAYLOAD:
    parser->frame.payload[parser->payload_index++] = byte;
    if (parser->payload_index >= parser->frame.payload_len) {
      parser->state = PROTOCOL_PSTATE_CRC0;
    }
    return PROTOCOL_PARSE_NEED_MORE;

  case PROTOCOL_PSTATE_CRC0:
    parser->crc_bytes[0] = byte;
    parser->state = PROTOCOL_PSTATE_CRC1;
    return PROTOCOL_PARSE_NEED_MORE;

  case PROTOCOL_PSTATE_CRC1:
    parser->crc_bytes[1] = byte;
    received_crc = read_u16_le(parser->crc_bytes);

    // Recompute CRC over the header + payload (same span the verifier covers).
    crc_input[0] = parser->frame.version;
    crc_input[1] = parser->frame.msg_type;
    write_u16_le(&crc_input[2], parser->frame.payload_len);
    memcpy(&crc_input[4], parser->frame.payload, parser->frame.payload_len);

    computed_crc = protocol_crc16_ccitt(
        crc_input, (size_t)(4u + parser->frame.payload_len));
    if (computed_crc != received_crc) {
      protocol_parser_reset(parser);
      return PROTOCOL_PARSE_ERROR;
    }

    parser->frame.crc16 = received_crc;
    *out_frame = parser->frame;
    protocol_parser_reset(parser);
    return PROTOCOL_PARSE_FRAME_READY;

  default:
    protocol_parser_reset(parser);
    return PROTOCOL_PARSE_ERROR;
  }
}

// ============================================================ Frame builder
// ======

protocol_status_t protocol_build_frame(const protocol_frame_t *frame,
                                       uint8_t *out_buf, size_t out_buf_size,
                                       size_t *out_len) {
  // Serialize a protocol_frame_t into a contiguous byte buffer with SOF,
  // header, payload and CRC trailer, ready for HAL_UART_Transmit.
  uint16_t crc;
  size_t frame_len;
  uint8_t crc_input[4 + PROTOCOL_MAX_PAYLOAD_SIZE];
  protocol_status_t status;

  if ((frame == NULL) || (out_buf == NULL) || (out_len == NULL)) {
    return PROTOCOL_STATUS_INVALID_ARG;
  }

  status = validate_frame_header(frame);
  if (status != PROTOCOL_STATUS_OK) {
    return status;
  }

  frame_len = (size_t)frame->payload_len + PROTOCOL_FRAME_OVERHEAD;
  if (out_buf_size < frame_len) {
    return PROTOCOL_STATUS_BUFFER_TOO_SMALL;
  }

  crc_input[0] = frame->version;
  crc_input[1] = frame->msg_type;
  write_u16_le(&crc_input[2], frame->payload_len);
  memcpy(&crc_input[4], frame->payload, frame->payload_len);
  crc = protocol_crc16_ccitt(crc_input, (size_t)(4u + frame->payload_len));

  out_buf[0] = PROTOCOL_SOF_0;
  out_buf[1] = PROTOCOL_SOF_1;
  out_buf[2] = frame->version;
  out_buf[3] = frame->msg_type;
  write_u16_le(&out_buf[4], frame->payload_len);
  memcpy(&out_buf[6], frame->payload, frame->payload_len);
  write_u16_le(&out_buf[6u + frame->payload_len], crc);

  *out_len = frame_len;
  return PROTOCOL_STATUS_OK;
}

// ============================================================ Payload parsing
// ====

protocol_status_t protocol_parse_attest_req(const protocol_frame_t *frame,
                                            protocol_attest_req_t *req) {
  // Unpack the fixed-layout attestation request from a validated frame.
  size_t offset = 0u;
  protocol_status_t status;

  if ((frame == NULL) || (req == NULL)) {
    return PROTOCOL_STATUS_INVALID_ARG;
  }

  status = validate_frame_header(frame);
  if (status != PROTOCOL_STATUS_OK) {
    return status;
  }

  if (frame->msg_type != PROTOCOL_MSG_ATTEST_REQ) {
    return PROTOCOL_STATUS_UNSUPPORTED_TYPE;
  }

  if (frame->payload_len != PROTOCOL_REQ_PAYLOAD_SIZE) {
    return PROTOCOL_STATUS_BAD_LENGTH;
  }

  memset(req, 0, sizeof(*req));

  req->counter = read_u32_le(&frame->payload[offset]);
  offset += 4u;

  req->profile_id = frame->payload[offset++];

  memcpy(req->nonce, &frame->payload[offset], PROTOCOL_NONCE_SIZE);
  offset += PROTOCOL_NONCE_SIZE;

  memcpy(req->expected_vs, &frame->payload[offset], PROTOCOL_VS_SIZE);
  offset += PROTOCOL_VS_SIZE;

  memcpy(req->auth_mac, &frame->payload[offset], PROTOCOL_AUTH_MAC_SIZE);

  return PROTOCOL_STATUS_OK;
}

// ============================================================ Response builder
// ===

protocol_status_t
protocol_build_attest_resp_frame(const protocol_attest_resp_t *resp,
                                 bool include_local_vs,
                                 protocol_frame_t *frame) {
  // Pack a typed response into a protocol_frame_t. The flags byte on the wire
  // reflects include_local_vs and the timing flag from resp->flags.
  size_t offset = 0u;
  uint8_t wire_flags;

  if ((resp == NULL) || (frame == NULL)) {
    return PROTOCOL_STATUS_INVALID_ARG;
  }

  memset(frame, 0, sizeof(*frame));
  frame->version = PROTOCOL_VERSION;
  frame->msg_type = PROTOCOL_MSG_ATTEST_RESP;

  write_u32_le(&frame->payload[offset], resp->counter);
  offset += 4u;

  wire_flags =
      include_local_vs
          ? (resp->flags | PROTOCOL_RESP_FLAG_LOCAL_VS_PRESENT)
          : (resp->flags & (uint8_t)(~PROTOCOL_RESP_FLAG_LOCAL_VS_PRESENT));

  frame->payload[offset++] = resp->profile_id;
  frame->payload[offset++] = resp->result;
  frame->payload[offset++] = wire_flags;

  if (include_local_vs) {
    memcpy(&frame->payload[offset], resp->local_vs, PROTOCOL_VS_SIZE);
    offset += PROTOCOL_VS_SIZE;
  }

  if ((wire_flags & PROTOCOL_RESP_FLAG_TIMING_PRESENT) != 0u) {
    protocol_write_timing(frame->payload, &offset, &resp->timing);
  }

  memcpy(&frame->payload[offset], resp->auth_mac, PROTOCOL_AUTH_MAC_SIZE);
  offset += PROTOCOL_AUTH_MAC_SIZE;

  frame->payload_len = (uint16_t)offset;
  return PROTOCOL_STATUS_OK;
}
