#!/usr/bin/env python3
"""Verify live persistence and lossless output during a sustained recording."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

LINES_PER_SECOND = 20
ARCHIVE_BYTES_PER_HOUR = 5_000_000
CHILD_EXIT_CODE = 42
COMMAND_TIMEOUT = 15
LINE_FORMAT = "{:06d} INFO build step completed; checking workspace and saving diagnostics"
WORKLOAD = """
import sys
import time

duration, rate, exit_code = map(int, sys.argv[1:4])
line_format = sys.argv[4]
start = time.monotonic()
for index in range(duration * rate):
    print(line_format.format(index), flush=True)
    time.sleep(max(0, start + (index + 1) / rate - time.monotonic()))
sys.exit(exit_code)
"""


def read_cli(binary, *args):
    return subprocess.check_output([binary, *args], timeout=COMMAND_TIMEOUT)


def watch_live_session(binary, db, recorder, seconds):
    start = time.monotonic()
    interval = min(10, seconds / 4)
    next_check = start + interval
    deadline = start + seconds + COMMAND_TIMEOUT
    counts = []
    session_id = None

    while recorder.poll() is None:
        now = time.monotonic()
        if now >= deadline:
            raise TimeoutError("Sustained recorder did not exit")
        if now >= next_check:
            sessions = json.loads(read_cli(binary, "ps", "--db", db, "--json"))
            if sessions:
                if len(sessions) != 1 or sessions[0]["status"] != "active":
                    raise ValueError(f"Expected one active recording, got {sessions}")
                session = sessions[0]
                if session_id is not None and session["session_id"] != session_id:
                    raise ValueError("Live session identity changed during recording")
                session_id = session["session_id"]
                count = session["event_count"]
                if not counts or count > counts[-1]:
                    counts.append(count)
            next_check = now + interval
        time.sleep(0.2)

    if recorder.returncode != CHILD_EXIT_CODE:
        raise ValueError(f"Recorder returned {recorder.returncode}, expected {CHILD_EXIT_CODE}")
    if len(counts) < 3:
        raise ValueError(f"Expected at least three advancing live checkpoints, got {counts}")
    return session_id, counts


def verify_events(source, envelopes, line_count):
    events = [envelope["event"] for envelope in envelopes]
    if not events or events[0]["type"] != "session_start" or events[-1]["type"] != "session_end":
        raise ValueError(f"{source}: missing session start or end")
    if [envelope["seq"] for envelope in envelopes] != list(range(1, len(events) + 1)):
        raise ValueError(f"{source}: event sequence is not contiguous")
    if events[-1]["total_events"] != len(events):
        raise ValueError(f"{source}: session end has incorrect event count")
    exits = [event["exit_code"] for event in events if event["type"] == "span_end"]
    if exits != [CHILD_EXIT_CODE]:
        raise ValueError(f"{source}: expected one span exit with code {CHILD_EXIT_CODE}, got {exits}")
    if any(event["type"] == "drop_marker" for event in events):
        raise ValueError(f"{source}: recorder reported dropped bytes")
    output = "".join(
        event["data"] for event in events
        if event["type"] == "stream_chunk" and event["channel"] == "stdout"
    )
    output = output.replace("\r\n", "\n")
    if not output.endswith("\n"):
        raise ValueError(f"{source}: final line is missing its newline")
    lines = output.removesuffix("\n").split("\n")
    if len(lines) != line_count:
        raise ValueError(f"{source}: expected {line_count} output lines, got {len(lines)}")
    for index, line in enumerate(lines):
        if line != LINE_FORMAT.format(index):
            raise ValueError(f"{source}: output mismatch at line {index + 1}")


def check(binary, seconds):
    with tempfile.TemporaryDirectory(prefix="devtape-sustained-") as directory:
        cwd = Path(directory)
        db = cwd / "session.db"
        tape = cwd / "session.tape"
        command = [
            binary, "record", "--db", db, "--out", tape, "--",
            sys.executable, "-c", WORKLOAD,
            str(seconds), str(LINES_PER_SECOND), str(CHILD_EXIT_CODE), LINE_FORMAT,
        ]
        with subprocess.Popen(
            command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL
        ) as recorder:
            try:
                session_id, checkpoints = watch_live_session(binary, db, recorder, seconds)
            finally:
                if recorder.poll() is None:
                    recorder.kill()

        if json.loads(read_cli(binary, "ps", "--db", db, "--json")):
            raise ValueError("Completed session still appears in the live session list")

        line_count = seconds * LINES_PER_SECOND
        archive = json.loads(read_cli(binary, "inspect", tape))
        if archive["manifest"]["session_id"] != session_id:
            raise ValueError("Archive and live session IDs differ")
        verify_events("archive", archive["events"], line_count)
        persisted = read_cli(binary, "tail", session_id, "--db", db, "--json")
        verify_events("SQLite", [json.loads(line) for line in persisted.splitlines()], line_count)

        size = tape.stat().st_size
        hourly_rate = size * 3600 / seconds
        print(f"{seconds}s recording: {line_count} output lines verified in archive and SQLite")
        print(f"Advancing live event counts: {checkpoints}")
        print(f"Archive: {size} bytes, {hourly_rate:,.0f} bytes/hour at the fixture rate")
        if size * 3600 >= ARCHIVE_BYTES_PER_HOUR * seconds:
            raise ValueError("Compressed archive failed the strict 5 MB/hour fixture budget")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="path to the release devtape executable")
    parser.add_argument("--seconds", type=int, default=60, help="duration (10–3600 seconds)")
    args = parser.parse_args()
    if not 10 <= args.seconds <= 3600:
        parser.error("--seconds must be between 10 and 3600")
    check(args.binary.resolve(strict=True), args.seconds)


if __name__ == "__main__":
    main()
