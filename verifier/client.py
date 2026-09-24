"""verifier.client — thin TCP client that talks to the ESP32 gateway.

One attestation = one short-lived TCP connection to the gateway, which transparently
relays the framed request to the STM32 prover over UART and relays the response back.
This module owns only the transport; framing/parsing/auth live in :mod:`verifier.wire`.
"""

from __future__ import annotations

import socket

from .models import AttestationResponse, Target, VerifierError
from .wire import build_request, parse_response, recv_exact_frame


class AttestationClient:
    def __init__(self, target: Target, timeout: float) -> None:
        # Bind the client to one target endpoint (the gateway) and a per-call socket timeout.
        self.target = target
        self.timeout = timeout

    def exchange(
        self, counter: int, profile_id: int, nonce: bytes, expected_vs: bytes
    ) -> AttestationResponse:
        # One request/response round-trip: build and send the framed request, read back a
        # complete response frame, then parse + authenticate it (the nonce is passed in so
        # parse_response can recompute the response MAC over it).

        frame = build_request(
            counter=counter, profile_id=profile_id, nonce=nonce, expected_vs=expected_vs
        )

        try:
            with socket.create_connection(
                (self.target.host, self.target.port), timeout=self.timeout
            ) as sock:
                sock.settimeout(self.timeout)
                sock.sendall(frame)
                response_frame = recv_exact_frame(sock)

        except socket.timeout as exc:
            raise VerifierError(
                f"timeout talking to gateway at {self.target.host}:{self.target.port}"
            ) from exc
        except TimeoutError as exc:
            raise VerifierError(
                f"timeout talking to gateway at {self.target.host}:{self.target.port}"
            ) from exc
        except OSError as exc:
            raise VerifierError(
                f"cannot connect to gateway at {self.target.host}:{self.target.port}: {exc}"
            ) from exc

        try:
            return parse_response(response_frame, nonce)
        except Exception as exc:
            raise VerifierError(f"received invalid response frame: {exc}") from exc
