#!/usr/bin/env python3
"""Verify simulator CLI output is stable across process hash seeds."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SIMULATOR = ROOT / "simulator/pagefrag_sim.py"
OUTPUTS = ("events.csv", "summary.csv", "timeline.csv")


def run(seed: int, hash_seed: int, output: Path) -> None:
    environment = os.environ.copy()
    environment["PYTHONHASHSEED"] = str(hash_seed)
    subprocess.run(
        (
            sys.executable,
            str(SIMULATOR),
            "--seed",
            str(seed),
            "--duration",
            "0.25",
            "--sample",
            "0.05",
            "--output",
            str(output),
        ),
        check=True,
        cwd=ROOT,
        env=environment,
        stdout=subprocess.DEVNULL,
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        first = base / "first"
        second = base / "second"
        alternate = base / "alternate"
        run(17, 1, first)
        run(17, 8675309, second)
        run(18, 1, alternate)

        for name in OUTPUTS:
            if (first / name).read_bytes() != (second / name).read_bytes():
                print(f"FAIL: {name} changes with PYTHONHASHSEED")
                return 1
        if (first / "events.csv").read_bytes() == (alternate / "events.csv").read_bytes():
            print("FAIL: changing the simulator seed did not change events.csv")
            return 1

    print("simulator CLI output is deterministic")
    return 0


if __name__ == "__main__":
    sys.exit(main())
