"""verifier.utils — small shared helpers for the verifier package."""

from __future__ import annotations

from .models import VerifierError


def decode_fixed_hex(value: str, expected_size: int, field_name: str) -> bytes:
    # Decode a hex string that MUST decode to exactly `expected_size` bytes
    # (e.g. a 16-byte nonce or a 32-byte VS). Both malformed hex and a wrong
    # length are reported as a VerifierError carrying the human-readable field name.
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise VerifierError(f"{field_name} is not valid hex") from exc
    if len(raw) != expected_size:
        raise VerifierError(
            f"{field_name} must be {expected_size} bytes, got {len(raw)}"
        )
    return raw
