"""verifier.models — value objects and the shared error type for the verifier.

These are immutable carriers for the data exchanged with the prover:
  - Target               : the host:port the verifier connects to (the ESP32 gateway).
  - AttestationTiming    : the prover-side cycle counters, optionally returned in the response.
  - AttestationResponse  : a fully parsed and authenticated response frame.
  - VerifierError        : the single error type raised across the package; main_cli()
                           turns it into a clean exit code + stderr message.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Target:
    host: str
    port: int

    @property
    def key(self) -> str:
        # Unique host:port identifier, used as the per-target key in the JSON state store.
        return f"{self.host}:{self.port}"


@dataclass(frozen=True)
class AttestationTiming:
    # Prover-side benchmark counters (raw Cortex-M cycle counts) for one attestation,
    # mirrored from the response's optional timing block. See cli.cycles_to_ms() for the
    # conversion to milliseconds using the prover's HCLK frequency.
    req_mac_cycles: int
    state_cycles: int
    compare_cycles: int
    response_mac_cycles: int
    total_cycles: int

    def ms(self, cycles: int, hclk_hz: int) -> float:
        return (cycles * 1000.0) / float(hclk_hz)


@dataclass(frozen=True)
class AttestationResponse:
    # One parsed response payload (see wire.parse_response). `local_vs` is present only
    # in debug builds (FLAG_LOCAL_VS_PRESENT); `timing` only when FLAG_TIMING_PRESENT.
    counter: int
    profile_id: int
    result: int
    flags: int
    local_vs: bytes
    auth_mac: bytes
    raw_frame: bytes
    timing: Optional[AttestationTiming] = None


class VerifierError(RuntimeError):
    # Domain error for any verifier-side failure (bad CLI args, protocol/parse errors,
    # missing state, etc.). Raised everywhere and handled centrally in cli.main_cli().
    pass
