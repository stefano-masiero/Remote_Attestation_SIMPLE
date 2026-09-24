"""verifier.state_store — persistent verifier state in a JSON file.

The verifier keeps two things per target endpoint (see report §2.2 / Listing 1):
  - last_counter : the highest accepted request counter, so every new request uses a
                   strictly greater value (freshness / replay protection on the host side).
  - profiles     : the enrolled expected_vs baseline for each attestation profile,
                   stored as hex. Indexing by target allows separate baselines per prover.

Writes are atomic (write to a temp file, then replace) to avoid corrupting state on crash.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from .constants import VS_SIZE
from .models import Target, VerifierError
from .utils import decode_fixed_hex


class StateStore:
    def __init__(self, path: Path) -> None:
        # Bind to a path and start with an empty in-memory view; load() is lazy.
        self.path = path
        self.data: dict[str, Any] = {"targets": {}}
        self._loaded = False

    def load(self) -> None:
        # Load state from disk once. A missing file is fine (fresh state); a present file
        # must be a JSON object with a dict 'targets', otherwise we refuse to continue.
        if self._loaded:
            return
        if self.path.exists():
            with self.path.open("r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if not isinstance(loaded, dict):
                raise VerifierError(f"state file {self.path} is not a JSON object")
            targets = loaded.get("targets", {})
            if not isinstance(targets, dict):
                raise VerifierError(f"state file {self.path} has invalid 'targets'")
            self.data = {"targets": targets}
        self._loaded = True

    def save(self) -> None:
        # Persist atomically: serialize to <path>.tmp then rename over the real file.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        with tmp_path.open("w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        tmp_path.replace(self.path)

    def _target_entry(self, target: Target) -> dict[str, Any]:
        # Get (or lazily create) the per-target record, ensuring its expected shape.
        self.load()
        targets = self.data.setdefault("targets", {})
        entry = targets.setdefault(target.key, {"last_counter": 0, "profiles": {}})
        if not isinstance(entry, dict):
            raise VerifierError(f"invalid state entry for target {target.key}")
        entry.setdefault("last_counter", 0)
        entry.setdefault("profiles", {})
        return entry

    def get_last_counter(self, target: Target) -> int:
        # Last accepted counter for this target (0 if never seen). Validated as a non-negative int.
        entry = self._target_entry(target)
        last_counter = entry.get("last_counter", 0)
        if not isinstance(last_counter, int) or last_counter < 0:
            raise VerifierError(f"invalid last_counter for target {target.key}")
        return last_counter

    def set_last_counter(self, target: Target, counter: int) -> None:
        # Advance the stored counter, never moving it backwards (keep the max seen).
        entry = self._target_entry(target)
        current = self.get_last_counter(target)
        entry["last_counter"] = max(current, counter)

    def get_expected_vs(self, target: Target, profile_id: int) -> Optional[bytes]:
        # Return the enrolled expected_vs for (target, profile), or None if not bootstrapped yet.
        entry = self._target_entry(target)
        profiles = entry["profiles"]
        profile_key = str(profile_id)
        profile_entry = profiles.get(profile_key)
        if profile_entry is None:
            return None
        if not isinstance(profile_entry, dict):
            raise VerifierError(
                f"invalid profile entry for {target.key} profile {profile_id}"
            )
        hex_value = profile_entry.get("expected_vs_hex")
        if hex_value is None:
            return None
        if not isinstance(hex_value, str):
            raise VerifierError(
                f"invalid expected_vs_hex for {target.key} profile {profile_id}"
            )
        return decode_fixed_hex(hex_value, VS_SIZE, field_name="stored expected_vs_hex")

    def set_expected_vs(
        self, target: Target, profile_id: int, expected_vs: bytes
    ) -> None:
        # Store/replace the expected_vs baseline (hex-encoded) for (target, profile).
        entry = self._target_entry(target)
        profiles = entry["profiles"]
        profile_entry = profiles.setdefault(str(profile_id), {})
        if not isinstance(profile_entry, dict):
            raise VerifierError(
                f"invalid profile entry for {target.key} profile {profile_id}"
            )
        profile_entry["expected_vs_hex"] = expected_vs.hex()
