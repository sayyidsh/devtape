#!/usr/bin/env python3
"""Measure interactive round-trip overhead on a Unix PTY."""

import argparse
import math
import os
from pathlib import Path
import pty
import select
import subprocess
import tempfile
import time

BUDGET_MS = 2.0
TIMEOUT_SECONDS = 10
WARMUP = 20
SAMPLES = 200
ROUNDS = 4
RESPONDER = [
    "/bin/sh",
    "-c",
    """set -e
stty -echo
printf 'READY\n'
while IFS= read -r request; do
    if [ "$request" = quit ]; then exit 0; fi
    printf 'PONG %s\n' "$request"
done""",
]


def expect_line(fd, buffer, expected):
    deadline = time.monotonic() + TIMEOUT_SECONDS
    while b"\n" not in buffer:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise TimeoutError(f"PTY did not return {expected!r}; buffered {buffer!r}")
        chunk = os.read(fd, 4096)
        if not chunk:
            raise EOFError(f"PTY closed while waiting for {expected!r}")
        buffer.extend(chunk)
    end = buffer.index(b"\n")
    actual = bytes(buffer[:end]).removesuffix(b"\r")
    del buffer[: end + 1]
    if actual != expected:
        raise ValueError(f"Expected {expected!r}, got {actual!r}")


def measure(binary, cwd, recording):
    tape = cwd / "latency.tape"
    command = RESPONDER
    if recording:
        command = [binary, "record", "--out", tape, "--db", cwd / "latency.db", "--", *RESPONDER]

    master, slave = pty.openpty()
    process = None
    try:
        try:
            process = subprocess.Popen(command, cwd=cwd, stdin=slave, stdout=slave)
        finally:
            os.close(slave)
        buffer = bytearray()
        expect_line(master, buffer, b"READY")
        times = []
        for index in range(WARMUP + SAMPLES):
            request = f"{index}\n".encode()
            expected = f"PONG {index}".encode()
            start = time.perf_counter_ns()
            os.write(master, request)
            expect_line(master, buffer, expected)
            elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
            if index >= WARMUP:
                times.append(elapsed_ms)
        os.write(master, b"quit\n")
        if process.wait(timeout=TIMEOUT_SECONDS):
            raise subprocess.CalledProcessError(process.returncode, command)
        if recording and tape.stat().st_size == 0:
            raise ValueError("DevTape produced an empty recording")
        return times
    finally:
        os.close(master)
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=TIMEOUT_SECONDS)


def percentiles(times):
    ordered = sorted(times)
    return {p: ordered[math.ceil(p * len(ordered) / 100) - 1] for p in (50, 95, 99)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="path to the release devtape executable")
    parser.add_argument(
        "--enforce-budget",
        action="store_true",
        help="fail if added p95 latency is 2 ms or more (use on a controlled runner)",
    )
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)

    samples = {False: [], True: []}
    for round_index in range(ROUNDS):
        # Alternate which session runs first to reduce order effects.
        for recording in (False, True) if round_index % 2 == 0 else (True, False):
            with tempfile.TemporaryDirectory(prefix="devtape-pty-bench-") as directory:
                samples[recording].extend(measure(binary, Path(directory), recording))

    direct = percentiles(samples[False])
    recorded = percentiles(samples[True])
    for label, stats in (("direct", direct), ("recorded", recorded)):
        values = " ".join(f"p{p}={ms:.3f} ms" for p, ms in stats.items())
        print(f"{label} ({ROUNDS * SAMPLES} samples): {values}")
    overhead = recorded[95] - direct[95]
    met_budget = overhead < BUDGET_MS
    status = "met" if met_budget else "exceeded"
    print(f"Added p95 latency: {overhead:+.3f} ms (< {BUDGET_MS:.1f} ms budget {status})")
    return int(args.enforce_budget and not met_budget)


if __name__ == "__main__":
    raise SystemExit(main())
