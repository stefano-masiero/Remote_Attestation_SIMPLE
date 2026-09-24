"""verifier.__main__ — module entry point for ``python3 -m verifier``.

This shim lets the package be executed straight from a checkout, without
installing it, by making sure the repository root is importable before handing
control to the package's real entry point. It re-runs the package under the
``__main__`` name so that the ``if __name__ == "__main__"`` block in
:mod:`verifier.__init__` fires and calls :func:`verifier.cli.main_cli`.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path


def _ensure_repo_root_on_path() -> None:
    # Prepend the repo root (the parent of this package) to sys.path so that the
    # absolute import `verifier.cli` resolves even when run from inside the package dir.
    repo_root = Path(__file__).resolve().parents[1]
    repo_root_str = str(repo_root)
    if repo_root_str not in sys.path:
        sys.path.insert(0, repo_root_str)


if __name__ == "__main__":
    _ensure_repo_root_on_path()
    runpy.run_module("verifier", run_name="__main__")
