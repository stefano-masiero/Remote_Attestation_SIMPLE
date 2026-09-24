"""verifier.wire — binary framing, CRC, and HMAC for the attestation protocol.

This module is the single source of truth for how requests are encoded and how
responses are decoded and authenticated. The on-wire frame is:

  SOF0 SOF1 | version | msg_type | payload_len (u16 LE) | payload | CRC16 (u16 LE)

The CRC is CRC-16/CCITT-FALSE (init 0xFFFF, poly 0x1021, no reflection, no final XOR)
and protects against accidental corruption on the UART/gateway path only — it is NOT a
security mechanism. End-to-end integrity and authenticity come from the HMAC-SHA256 tag
computed under K_AUTH over the authenticated fields (request) or over the response fields
including the original request nonce (response).
"""

from __future__ import annotations

import hashlib
import hmac
import socket
import struct
from typing import Optional

from .constants import (
    AUTH_MAC_SIZE,
    FLAG_LOCAL_VS_PRESENT,
    FLAG_TIMING_PRESENT,
    KAUTH,
    MSG_ATTEST_REQ,
    MSG_ATTEST_RESP,
    NONCE_SIZE,
    REQ_PAYLOAD_SIZE,
    RESP_PAYLOAD_MIN_SIZE,
    SOF0,
    SOF1,
    TIMING_SIZE,
    VERSION,
    VS_SIZE,
)
from .models import AttestationResponse, AttestationTiming, VerifierError

# ============================================================ CRC =============


def crc16_ccitt(data: bytes) -> int:
    # CRC-16/CCITT-FALSE over `data`. Both endpoints use this exact variant so there is no
    # ambiguity between the several mutually incompatible "CRC-16" definitions in the wild.
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


# ================================================ Authenticated-data builders =


def build_req_auth(
    counter: int, profile_id: int, nonce: bytes, expected_vs: bytes
) -> bytes:
    # Exact byte sequence the request MAC is computed over. Includes version+type so a
    # frame can't be replayed as a different message kind. Must match the prover's view.
    return (
        bytes([VERSION, MSG_ATTEST_REQ])
        + struct.pack("<I", counter)
        + bytes([profile_id])
        + nonce
        + expected_vs
    )


def encode_timing(timing: AttestationTiming) -> bytes:
    # Serialize the 5 prover cycle counters as little-endian uint32, in canonical order.
    return struct.pack(
        "<IIIII",
        timing.req_mac_cycles,
        timing.state_cycles,
        timing.compare_cycles,
        timing.response_mac_cycles,
        timing.total_cycles,
    )


def decode_timing(payload: bytes, offset: int) -> tuple[AttestationTiming, int]:
    # Read the timing block at `offset`; returns the parsed timing and the new offset.
    if len(payload) < offset + TIMING_SIZE:
        raise VerifierError("response timing block is truncated")
    values = struct.unpack_from("<IIIII", payload, offset)
    return AttestationTiming(*values), offset + TIMING_SIZE


def build_resp_auth(
    counter: int,
    profile_id: int,
    result: int,
    flags: int,
    nonce: bytes,
    local_vs: bytes,
    timing: Optional[AttestationTiming],
) -> bytes:
    # Reconstruct the exact byte sequence the response MAC is computed over, so the
    # verifier can recompute and compare it. The nonce (echoed from the request) binds the
    # response to this specific challenge. Optional fields are appended iff their flag is set.
    out = (
        bytes([VERSION, MSG_ATTEST_RESP])
        + struct.pack("<I", counter)
        + bytes([profile_id, result, flags])
        + nonce
    )
    if flags & FLAG_LOCAL_VS_PRESENT:
        out += local_vs
    if flags & FLAG_TIMING_PRESENT:
        if timing is None:
            raise VerifierError(
                "response says timing is present but no timing was parsed"
            )
        out += encode_timing(timing)
    return out


# ================================================================ Request =====


def build_request(
    counter: int, profile_id: int, nonce: bytes, expected_vs: bytes
) -> bytes:
    # Build a complete, framed, authenticated request ready to put on the socket.
    if len(nonce) != NONCE_SIZE:
        raise VerifierError(f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")
    if len(expected_vs) != VS_SIZE:
        raise VerifierError(
            f"expected_vs must be {VS_SIZE} bytes, got {len(expected_vs)}"
        )
    # 1) MAC the authenticated view, 2) lay out the payload, 3) frame it with header + CRC.
    auth_input = build_req_auth(counter, profile_id, nonce, expected_vs)
    auth_mac = hmac.new(KAUTH, auth_input, hashlib.sha256).digest()
    payload = (
        struct.pack("<I", counter)
        + bytes([profile_id])
        + nonce
        + expected_vs
        + auth_mac
    )
    if len(payload) != REQ_PAYLOAD_SIZE:
        raise VerifierError(f"internal error: request payload has size {len(payload)}")
    hdr = bytes([VERSION, MSG_ATTEST_REQ]) + struct.pack("<H", len(payload))
    crc = crc16_ccitt(hdr + payload)  # CRC covers header + payload (not the SOF bytes)
    return bytes([SOF0, SOF1]) + hdr + payload + struct.pack("<H", crc)


# ================================================================ Receive ======


def recv_exact_frame(sock: socket.socket) -> bytes:
    # Read from the socket until one full frame is buffered, then return exactly that frame.
    # The header's length field tells us the total size; we keep reading until we have it.
    buf = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise VerifierError("socket closed before full frame")
        buf.extend(chunk)
        if len(buf) < 6:
            continue  # not enough yet to even read SOF + header + length
        if buf[0] != SOF0 or buf[1] != SOF1:
            raise VerifierError(f"bad SOF: {buf[:2].hex()}")
        payload_len = struct.unpack_from("<H", buf, 4)[0]
        total = (
            2 + 1 + 1 + 2 + payload_len + 2
        )  # SOF(2)+ver(1)+type(1)+len(2)+payload+CRC(2)
        if len(buf) >= total:
            return bytes(buf[:total])


# ================================================================ Response =====


def parse_response(frame: bytes, nonce: bytes) -> AttestationResponse:
    # Validate framing, CRC and length, parse the fixed + optional fields, then verify the
    # response HMAC against the locally recomputed one. `nonce` is the request nonce, needed
    # to reconstruct the authenticated response view.
    if len(nonce) != NONCE_SIZE:
        raise VerifierError(f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")
    if len(frame) < 2 + 1 + 1 + 2 + RESP_PAYLOAD_MIN_SIZE + 2:
        raise VerifierError("response frame too short")
    if frame[0] != SOF0 or frame[1] != SOF1:
        raise VerifierError("bad SOF in response")

    version = frame[2]
    msg_type = frame[3]
    payload_len = struct.unpack_from("<H", frame, 4)[0]
    total_len = 2 + 1 + 1 + 2 + payload_len + 2
    if len(frame) != total_len:
        raise VerifierError(
            f"response frame has wrong size: got {len(frame)}, expected {total_len}"
        )
    if version != VERSION or msg_type != MSG_ATTEST_RESP:
        raise VerifierError(
            f"unexpected version/type in response: {version}/{msg_type}"
        )

    # CRC check covers header + payload (bytes [2 : 6+payload_len]); compare against trailer.
    payload = frame[6 : 6 + payload_len]
    crc_rx = struct.unpack_from("<H", frame, 6 + payload_len)[0]
    crc_calc = crc16_ccitt(frame[2 : 6 + payload_len])
    if crc_rx != crc_calc:
        raise VerifierError(f"bad CRC: rx=0x{crc_rx:04x} calc=0x{crc_calc:04x}")

    if payload_len < RESP_PAYLOAD_MIN_SIZE:
        raise VerifierError(f"unexpected response payload length: {payload_len}")

    # Fixed header fields.
    counter = struct.unpack_from("<I", payload, 0)[0]
    profile_id = payload[4]
    result = payload[5]
    flags = payload[6]
    offset = 7

    # Optional local_vs (debug build only).
    local_vs = b""
    if flags & FLAG_LOCAL_VS_PRESENT:
        if payload_len < offset + VS_SIZE + AUTH_MAC_SIZE:
            raise VerifierError(
                "response says local_vs is present but payload length is too short"
            )
        local_vs = payload[offset : offset + VS_SIZE]
        offset += VS_SIZE

    # Optional timing block.
    timing: Optional[AttestationTiming] = None
    if flags & FLAG_TIMING_PRESENT:
        timing, offset = decode_timing(payload, offset)

    # After the optional fields, exactly the MAC must remain — cross-check length vs flags.
    expected_payload_len = offset + AUTH_MAC_SIZE
    if payload_len != expected_payload_len:
        raise VerifierError(
            f"response payload length mismatch: got {payload_len}, expected {expected_payload_len} from flags"
        )

    auth_mac = payload[offset : offset + AUTH_MAC_SIZE]
    offset += AUTH_MAC_SIZE
    if len(auth_mac) != AUTH_MAC_SIZE:
        raise VerifierError("bad response auth MAC length")
    if offset != payload_len:
        raise VerifierError("response payload parsing did not end on payload boundary")

    # Authenticity: recompute the response MAC under K_AUTH over the reconstructed view and
    # compare in constant time. Any mismatch means the response is forged or corrupted.
    expected_mac = hmac.new(
        KAUTH,
        build_resp_auth(counter, profile_id, result, flags, nonce, local_vs, timing),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(expected_mac, auth_mac):
        raise VerifierError("response auth MAC mismatch")

    return AttestationResponse(
        counter=counter,
        profile_id=profile_id,
        result=result,
        flags=flags,
        local_vs=local_vs,
        auth_mac=auth_mac,
        raw_frame=frame,
        timing=timing,
    )
