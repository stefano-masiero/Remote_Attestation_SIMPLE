"""verifier.cli — command-line front end and orchestration for the verifier.

This module wires everything together: it parses CLI arguments, resolves the target
and the per-profile expected_vs, drives one of three flows, and reports results.

Flows:
  - bootstrap   : two-step enrollment. Send a request with a null expected_vs, learn the
                  prover's local_vs, re-attest with it, and (on success) store it as the
                  baseline. Convenient for the lab; NOT acceptable in a real deployment,
                  where the baseline must come from trusted provisioning.
  - single      : one attestation against the stored/overridden baseline.
  - repeated    : N attestations with benchmark statistics (and optional CSV export).

Exit codes: 0 success, 2 attestation failure, 3 stale counter, 4 other prover failure,
1 verifier-side error (raised as VerifierError and handled in main_cli).
"""

from __future__ import annotations

import argparse
import csv
import secrets
import statistics
import sys
import time
from pathlib import Path
from typing import Optional

from .client import AttestationClient
from .constants import (
    NONCE_SIZE,
    PROFILE_NAMES,
    RESULT_ATTESTATION_FAILURE,
    RESULT_NAMES,
    RESULT_STALE_COUNTER,
    RESULT_SUCCESS,
    VS_SIZE,
)
from .models import AttestationResponse, AttestationTiming, Target, VerifierError
from .state_store import StateStore
from .utils import decode_fixed_hex

# Default prover core clock, used to turn raw cycle counters into milliseconds.
DEFAULT_HCLK_HZ = 250_000_000


# ============================================================ Small helpers ===


def cycles_to_ms(cycles: int, hclk_hz: int) -> float:
    return (cycles * 1000.0) / float(hclk_hz)


def make_nonce(args: argparse.Namespace) -> bytes:
    # Pick the request nonce: explicit hex, the fixed 00..0f test vector, or a random one.
    if args.nonce_hex is not None:
        return decode_fixed_hex(args.nonce_hex, NONCE_SIZE, field_name="nonce")
    if args.fixed_nonce:
        return bytes(range(NONCE_SIZE))
    return secrets.token_bytes(NONCE_SIZE)


def parse_target(args: argparse.Namespace) -> Target:
    # Resolve the gateway endpoint, preferring the combined --tcp HOST:PORT over --host/--port.
    if args.tcp is not None:
        if ":" not in args.tcp:
            raise VerifierError("--tcp must be HOST:PORT")
        host, port_text = args.tcp.rsplit(":", 1)
        if not host:
            raise VerifierError("--tcp host is empty")
        try:
            port = int(port_text)
        except ValueError as exc:
            raise VerifierError("--tcp port is not an integer") from exc
        return Target(host=host, port=port)
    return Target(host=args.host, port=args.port)


# ============================================================ Argument parsing =


def parse_args() -> argparse.Namespace:
    # Define and validate CLI arguments.
    parser = argparse.ArgumentParser(
        description="Unified verifier for the STM32 remote attestation project"
    )
    parser.add_argument("--tcp", help="target as HOST:PORT")
    parser.add_argument("--host", default="192.168.4.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--profile", type=int, choices=(1, 2, 3), required=True)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--counter", type=int, help="override request counter")
    parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="learn local_vs for the selected profile and retry automatically",
    )
    parser.add_argument(
        "--expected-vs-hex",
        help="32-byte expected VS in hex; overrides the stored value",
    )
    parser.add_argument("--nonce-hex", help="16-byte nonce in hex")
    parser.add_argument(
        "--fixed-nonce",
        action="store_true",
        help="use 00..0f as nonce instead of a random nonce",
    )
    parser.add_argument("--state-file", default="verifier/verifier_state.json")
    parser.add_argument(
        "--no-state",
        action="store_true",
        help="do not read or write verifier_state.json",
    )
    parser.add_argument(
        "--adopt-local-vs",
        action="store_true",
        help="on mismatch, store local_vs returned by the prover",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="run N consecutive attestations and print benchmark statistics",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        help="write per-run benchmark measurements to this CSV file",
    )
    parser.add_argument(
        "--hclk-hz",
        type=int,
        default=DEFAULT_HCLK_HZ,
        help=f"STM32 HCLK frequency used to convert cycles to ms (default: {DEFAULT_HCLK_HZ})",
    )
    args = parser.parse_args()
    # Cross-argument sanity checks (argparse can't express these on its own).
    if args.repeat <= 0:
        raise VerifierError("--repeat must be > 0")
    if args.hclk_hz <= 0:
        raise VerifierError("--hclk-hz must be > 0")
    if args.bootstrap and args.repeat != 1:
        raise VerifierError(
            "--repeat is for normal attestations; bootstrap always performs its two-step flow"
        )
    return args


# ============================================================ Printing helpers =


def print_timing(prefix: str, timing: AttestationTiming, hclk_hz: int) -> None:
    # Print the prover-side benchmark counters, once as raw cycles and once converted to ms.
    print(
        f"{prefix} timing_cycles "
        f"req_mac={timing.req_mac_cycles} "
        f"state={timing.state_cycles} "
        f"compare={timing.compare_cycles} "
        f"resp_mac={timing.response_mac_cycles} "
        f"total={timing.total_cycles}"
    )
    print(
        f"{prefix} timing_ms "
        f"req_mac={cycles_to_ms(timing.req_mac_cycles, hclk_hz):.6f} "
        f"state={cycles_to_ms(timing.state_cycles, hclk_hz):.6f} "
        f"compare={cycles_to_ms(timing.compare_cycles, hclk_hz):.6f} "
        f"resp_mac={cycles_to_ms(timing.response_mac_cycles, hclk_hz):.6f} "
        f"total={cycles_to_ms(timing.total_cycles, hclk_hz):.6f}"
    )


def print_response(
    prefix: str, response: AttestationResponse, hclk_hz: Optional[int] = None
) -> None:
    # Print a response in a readable format, including local_vs and timing when present.
    result_name = RESULT_NAMES.get(response.result, f"UNKNOWN_0x{response.result:02X}")
    print(
        f"{prefix} counter={response.counter} "
        f"profile={response.profile_id} "
        f"result=0x{response.result:02x}({result_name}) "
        f"flags=0x{response.flags:02x}"
    )
    if response.local_vs:
        print(f"{prefix} local_vs={response.local_vs.hex()}")
    else:
        print(f"{prefix} local_vs=<absent>")
    if response.timing is not None and hclk_hz is not None:
        print_timing(prefix, response.timing, hclk_hz)


# ============================================================ State helpers ====


def choose_initial_counter(
    args: argparse.Namespace, store: Optional[StateStore], target: Target
) -> int:
    # Pick the counter for the first request: explicit override, else last-stored + 1, else 1.
    if args.counter is not None:
        if args.counter <= 0:
            raise VerifierError("--counter must be > 0")
        return args.counter
    if store is None:
        return 1
    return store.get_last_counter(target) + 1


def resolve_expected_vs(
    args: argparse.Namespace, store: Optional[StateStore], target: Target
) -> bytes:
    # Determine the expected VS to attest against: CLI override, else the enrolled baseline.
    if args.expected_vs_hex is not None:
        return decode_fixed_hex(args.expected_vs_hex, VS_SIZE, field_name="expected VS")
    if store is None:
        raise VerifierError(
            "no expected VS available: pass --expected-vs-hex or enable state and bootstrap first"
        )
    expected_vs = store.get_expected_vs(target, args.profile)
    if expected_vs is None:
        raise VerifierError(
            f"no stored expected VS for target {target.key} profile {args.profile}; run with --bootstrap first"
        )
    return expected_vs


def update_counter_if_needed(
    store: Optional[StateStore], target: Target, response: AttestationResponse
) -> None:
    # Persist the counter actually accepted by the prover (it advances even on failure,
    # because the prover consumes the counter once the request authenticates — see report §3.2).
    if store is not None:
        store.set_last_counter(target, response.counter)


def maybe_store_vs(
    store: Optional[StateStore], target: Target, profile_id: int, expected_vs: bytes
) -> None:
    # Persist an expected VS baseline if state is enabled (no-op under --no-state).
    if store is not None:
        store.set_expected_vs(target, profile_id, expected_vs)


def exchange_with_rtt(
    client: AttestationClient,
    counter: int,
    profile_id: int,
    nonce: bytes,
    expected_vs: bytes,
) -> tuple[AttestationResponse, float]:
    # One exchange wrapped with a host-side round-trip timer (wall-clock ms, incl. network).
    t0 = time.perf_counter()
    response = client.exchange(
        counter=counter, profile_id=profile_id, nonce=nonce, expected_vs=expected_vs
    )
    rtt_ms = (time.perf_counter() - t0) * 1000.0
    return response, rtt_ms


# ============================================================ Bootstrap flow ===


def run_bootstrap(
    client: AttestationClient,
    args: argparse.Namespace,
    store: Optional[StateStore],
    target: Target,
) -> int:
    # Two-step enrollment: (1) attest with a null VS to learn the prover's local_vs, then
    # (2) re-attest with that value; on success, store it as the profile baseline.
    nonce1 = make_nonce(args)
    counter1 = choose_initial_counter(args, store, target)
    zero_vs = bytes(VS_SIZE)

    print(
        f"[1] bootstrap request for profile {args.profile} ({PROFILE_NAMES[args.profile]})"
    )
    print(f"[1] nonce={nonce1.hex()}")
    response1, rtt1_ms = exchange_with_rtt(
        client,
        counter=counter1,
        profile_id=args.profile,
        nonce=nonce1,
        expected_vs=zero_vs,
    )
    update_counter_if_needed(store, target, response1)
    print_response("[1]", response1, args.hclk_hz)
    print(f"[1] rtt_ms={rtt1_ms:.3f}")

    # Step 1 is expected to fail attestation (null VS won't match) but must come back
    # well-formed, on the right profile, and carry local_vs — otherwise we can't enroll.
    if response1.profile_id != args.profile:
        raise VerifierError(
            f"response profile mismatch in bootstrap step 1: expected {args.profile}, got {response1.profile_id}"
        )
    if response1.result not in (RESULT_SUCCESS, RESULT_ATTESTATION_FAILURE):
        raise VerifierError(
            f"bootstrap step 1 returned 0x{response1.result:02x}; expected SUCCESS or ATTESTATION_FAILURE"
        )
    if not response1.local_vs:
        raise VerifierError(
            "bootstrap cannot continue because the prover did not include local_vs"
        )

    nonce2 = make_nonce(args)
    # Fresh counter strictly greater than what step 1 consumed.
    counter2 = max(counter1, response1.counter) + 1
    print()
    print("[2] retry with learned local_vs")
    print(f"[2] nonce={nonce2.hex()}")
    response2, rtt2_ms = exchange_with_rtt(
        client,
        counter=counter2,
        profile_id=args.profile,
        nonce=nonce2,
        expected_vs=response1.local_vs,
    )
    update_counter_if_needed(store, target, response2)
    print_response("[2]", response2, args.hclk_hz)
    print(f"[2] rtt_ms={rtt2_ms:.3f}")

    # Step 2 must now succeed; if it does, the learned value is a usable baseline.
    if response2.profile_id != args.profile:
        raise VerifierError(
            f"response profile mismatch in bootstrap step 2: expected {args.profile}, got {response2.profile_id}"
        )
    if response2.result != RESULT_SUCCESS:
        raise VerifierError(
            f"bootstrap step 2 expected SUCCESS, got 0x{response2.result:02x}"
        )

    maybe_store_vs(store, target, args.profile, response1.local_vs)
    print()
    print(f"Stored expected VS for profile {args.profile}: {response1.local_vs.hex()}")
    return 0


# ============================================================ Benchmark / CSV ==


def timing_to_row(
    iteration: int,
    counter: int,
    response: AttestationResponse,
    rtt_ms: float,
    hclk_hz: int,
) -> dict[str, object]:
    # Flatten one response (+ host RTT) into a CSV row; timing fields are added when present.
    result_name = RESULT_NAMES.get(response.result, f"UNKNOWN_0x{response.result:02X}")
    row: dict[str, object] = {
        "iteration": iteration,
        "counter": counter,
        "response_counter": response.counter,
        "profile": response.profile_id,
        "result": f"0x{response.result:02x}",
        "result_name": result_name,
        "flags": f"0x{response.flags:02x}",
        "rtt_ms": f"{rtt_ms:.6f}",
    }
    if response.timing is not None:
        t = response.timing
        for name, cycles in (
            ("req_mac", t.req_mac_cycles),
            ("state", t.state_cycles),
            ("compare", t.compare_cycles),
            ("resp_mac", t.response_mac_cycles),
            ("total", t.total_cycles),
        ):
            row[f"{name}_cycles"] = cycles
            row[f"{name}_ms"] = f"{cycles_to_ms(cycles, hclk_hz):.9f}"
    return row


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    # Write rows to CSV, deriving the header from the union of keys (preserving first-seen order).
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def print_benchmark_summary(responses: list[AttestationResponse], hclk_hz: int) -> None:
    # Aggregate prover timing over the successful runs into mean/stdev/min/max per stage.
    timings = [r.timing for r in responses if r.timing is not None]
    if not timings:
        print(
            "No prover timing block was returned. Rebuild the STM32 firmware with ATTESTATION_BENCHMARK=1u."
        )
        return

    print()
    print("Benchmark summary, successful runs only:")
    print("operation, mean_ms, stdev_ms, min_ms, max_ms")
    for label, getter in (
        ("request_hmac", lambda t: t.req_mac_cycles),
        ("state_derivation", lambda t: t.state_cycles),
        ("compare", lambda t: t.compare_cycles),
        ("response_hmac", lambda t: t.response_mac_cycles),
        ("total_privileged", lambda t: t.total_cycles),
    ):
        values = [cycles_to_ms(getter(t), hclk_hz) for t in timings]
        stdev = statistics.stdev(values) if len(values) >= 2 else 0.0
        print(
            f"{label}, {statistics.mean(values):.6f}, {stdev:.6f}, {min(values):.6f}, {max(values):.6f}"
        )


# ============================================================ Repeated flow ====


def run_repeated_attestations(
    client: AttestationClient,
    args: argparse.Namespace,
    store: Optional[StateStore],
    target: Target,
) -> int:
    # Run --repeat attestations with consecutive counters and report benchmark stats.
    # Stops early on the first non-success and returns a result-specific exit code.
    expected_vs = resolve_expected_vs(args, store, target)
    start_counter = choose_initial_counter(args, store, target)
    rows: list[dict[str, object]] = []
    successful: list[AttestationResponse] = []

    print(
        f"Running {args.repeat} attestations for profile {args.profile} ({PROFILE_NAMES[args.profile]})"
    )

    for i in range(args.repeat):
        counter = start_counter + i
        nonce = make_nonce(args)
        response, rtt_ms = exchange_with_rtt(
            client,
            counter=counter,
            profile_id=args.profile,
            nonce=nonce,
            expected_vs=expected_vs,
        )
        update_counter_if_needed(store, target, response)
        rows.append(timing_to_row(i + 1, counter, response, rtt_ms, args.hclk_hz))

        result_name = RESULT_NAMES.get(
            response.result, f"UNKNOWN_0x{response.result:02X}"
        )
        timing_text = ""
        if response.timing is not None:
            timing_text = f" total={cycles_to_ms(response.timing.total_cycles, args.hclk_hz):.6f} ms"
        print(
            f"[{i + 1}/{args.repeat}] counter={counter} result=0x{response.result:02x}({result_name}) rtt={rtt_ms:.3f} ms{timing_text}"
        )

        # A profile mismatch is a protocol error, not a benign failure: abort hard.
        if response.profile_id != args.profile:
            print_response("[bad]", response, args.hclk_hz)
            raise VerifierError(
                f"response profile mismatch: expected {args.profile}, got {response.profile_id}"
            )
        if response.result == RESULT_SUCCESS:
            successful.append(response)
        else:
            # Non-success: dump the offending response, flush whatever CSV we have, and stop.
            print_response("[fail]", response, args.hclk_hz)
            if args.csv is not None:
                write_csv(args.csv, rows)
                print(f"Wrote partial CSV to {args.csv}")
            return 2 if response.result == RESULT_ATTESTATION_FAILURE else 4

    if args.csv is not None:
        write_csv(args.csv, rows)
        print(f"Wrote CSV to {args.csv}")

    print_benchmark_summary(successful, args.hclk_hz)
    return 0


# ============================================================ Single flow ======


def run_attestation(
    client: AttestationClient,
    args: argparse.Namespace,
    store: Optional[StateStore],
    target: Target,
) -> int:
    # Dispatch to the repeated path when --repeat > 1; otherwise run exactly one attestation.
    if args.repeat > 1:
        return run_repeated_attestations(client, args, store, target)

    expected_vs = resolve_expected_vs(args, store, target)
    counter = choose_initial_counter(args, store, target)
    nonce = make_nonce(args)

    print(
        f"Requesting attestation for profile {args.profile} ({PROFILE_NAMES[args.profile]})"
    )
    print(f"counter={counter}")
    print(f"nonce={nonce.hex()}")
    print(f"expected_vs={expected_vs.hex()}")

    response, rtt_ms = exchange_with_rtt(
        client,
        counter=counter,
        profile_id=args.profile,
        nonce=nonce,
        expected_vs=expected_vs,
    )
    update_counter_if_needed(store, target, response)
    print_response("[resp]", response, args.hclk_hz)
    print(f"[resp] rtt_ms={rtt_ms:.3f}")

    if args.csv is not None:
        write_csv(args.csv, [timing_to_row(1, counter, response, rtt_ms, args.hclk_hz)])
        print(f"Wrote CSV to {args.csv}")

    if response.profile_id != args.profile:
        raise VerifierError(
            f"response profile mismatch: expected {args.profile}, got {response.profile_id}"
        )

    # Map the prover result onto a printed verdict and a process exit code.
    if response.result == RESULT_SUCCESS:
        print("Attestation OK.")
        return 0

    if response.result == RESULT_ATTESTATION_FAILURE:
        print("Attestation FAILED: expected VS does not match the prover state.")
        if response.local_vs:
            print(f"Prover local_vs={response.local_vs.hex()}")
            # Optionally re-baseline to the prover's current state (e.g. after a legit update).
            if args.adopt_local_vs:
                maybe_store_vs(store, target, args.profile, response.local_vs)
                print(
                    "Stored prover local_vs as the new expected VS because --adopt-local-vs was set."
                )
        return 2

    if response.result == RESULT_STALE_COUNTER:
        print("Request rejected because the counter is stale.")
        return 3

    print(
        f"Request failed with result 0x{response.result:02x} ({RESULT_NAMES.get(response.result, 'UNKNOWN')})."
    )
    return 4


# ============================================================ Entry points =====


def main() -> int:
    # Verifier CLI entry point: parse args, open state (unless --no-state), run the chosen
    # flow, and always persist state in a finally block so counters/baselines survive errors.
    args = parse_args()
    target = parse_target(args)
    store = None if args.no_state else StateStore(Path(args.state_file))
    if store is not None:
        store.load()

    client = AttestationClient(target=target, timeout=args.timeout)
    exit_code = 0

    try:
        if args.bootstrap:
            exit_code = run_bootstrap(client, args, store, target)
        else:
            exit_code = run_attestation(client, args, store, target)
    finally:
        if store is not None:
            store.save()
    return exit_code


def main_cli() -> None:
    # Wrapper that converts a clean exit code into SystemExit and turns any VerifierError
    # into a one-line stderr message with exit status 1.
    try:
        raise SystemExit(main())
    except VerifierError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        raise SystemExit(1)
