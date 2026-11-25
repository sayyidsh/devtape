#!/usr/bin/env python3
"""Measure steady-state CPU and resident memory of the Linux recorder."""

import argparse
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

CPU_BUDGET_PERCENT = 2.0
WARMUP_SECONDS = 1
SAMPLE_SECONDS = 10
POLL_SECONDS = 0.2
TIMEOUT_SECONDS = 10

# This child writes 100 lines of 256 bytes per second. In proxy mode it also
# sends two HTTP requests per second through the recorder's loopback proxy.
WORKLOAD = """
import http.client
import os
from pathlib import Path
import sys
import time
from urllib.parse import urlsplit

origin = sys.argv[1]
proxy = urlsplit(os.environ["HTTP_PROXY"]) if origin else None
message = b"Recorded command output with representative words and terminal line breaks. "
stop = Path("stop")
start = time.monotonic()
for index in range(6000):
    if stop.exists():
        break
    line = f"{index:06} ".encode() + (message * 4)[:248] + b"\\n"
    os.write(1, line)
    if proxy and index % 50 == 0:
        connection = http.client.HTTPConnection(proxy.hostname, proxy.port, timeout=3)
        try:
            connection.request("GET", origin)
            response = connection.getresponse()
            if response.status != 200 or response.read() != b"ok":
                raise RuntimeError("Unexpected response from the DevTape proxy")
        finally:
            connection.close()
    if index == 0:
        Path("ready").touch()
    time.sleep(max(0, start + (index + 1) / 100 - time.monotonic()))
else:
    raise TimeoutError("Benchmark did not signal the workload to stop")
"""


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_):
        pass


def process_sample(pid):
    # /proc fields after the final closing parenthesis start at field 3.
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    cpu_ticks = int(fields[11]) + int(fields[12])  # utime and stime, fields 14 and 15
    resident_pages = int(fields[21])  # rss, field 24
    return cpu_ticks, resident_pages


def measure_process(process, ready):
    deadline = time.monotonic() + TIMEOUT_SECONDS
    while not ready.exists():
        if process.poll() is not None:
            raise RuntimeError(f"Recorder exited before startup ({process.returncode})")
        if time.monotonic() >= deadline:
            raise TimeoutError("Recorder workload did not become ready")
        time.sleep(POLL_SECONDS)

    time.sleep(WARMUP_SECONDS)
    ticks_start, peak_pages = process_sample(process.pid)
    start = time.monotonic()
    end = start
    while end - start < SAMPLE_SECONDS:
        time.sleep(POLL_SECONDS)
        ticks_end, pages = process_sample(process.pid)
        end = time.monotonic()
        peak_pages = max(peak_pages, pages)

    cpu_percent = (ticks_end - ticks_start) / os.sysconf("SC_CLK_TCK") / (end - start) * 100
    return cpu_percent, peak_pages * os.sysconf("SC_PAGE_SIZE")


def verify_archive(binary, tape, origin):
    output = subprocess.check_output([binary, "inspect", tape], timeout=TIMEOUT_SECONDS)
    events = [item["event"] for item in json.loads(output)["events"]]
    if not any(event["type"] == "stream_chunk" for event in events):
        raise ValueError("Benchmark recorded no PTY output")
    if any(event["type"] == "drop_marker" for event in events):
        raise ValueError("Benchmark recorder dropped data")
    exchanges = sum(
        event.get("extension_id") == "ext.http.v1" and event.get("event_name") == "http_exchange"
        for event in events
    )
    if bool(exchanges) != bool(origin):
        raise ValueError(f"Unexpected number of recorded HTTP exchanges: {exchanges}")
    return exchanges


def benchmark(binary, origin=""):
    with tempfile.TemporaryDirectory(prefix="devtape-resource-bench-") as directory:
        cwd = Path(directory)
        tape = cwd / "session.tape"
        stop = cwd / "stop"
        command = [binary, "record", "--out", tape, "--db", cwd / "session.db"]
        if origin:
            command.append("--net")
        command.extend(["--", sys.executable, "-c", WORKLOAD, origin])
        with subprocess.Popen(
            command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL
        ) as process:
            try:
                cpu, rss = measure_process(process, cwd / "ready")
            finally:
                stop.touch()
                try:
                    status = process.wait(timeout=TIMEOUT_SECONDS)
                except subprocess.TimeoutExpired:
                    process.kill()
                    raise
            if status:
                raise subprocess.CalledProcessError(status, command)
        return cpu, rss, verify_archive(binary, tape, origin)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="path to the release devtape executable")
    parser.add_argument(
        "--enforce-budget", action="store_true",
        help="fail if CPU or RSS exceeds its budget (use on a controlled runner)",
    )
    args = parser.parse_args()
    if sys.platform != "linux" or not Path("/proc/self/stat").is_file():
        parser.error("this benchmark requires Linux procfs")
    binary = args.binary.resolve(strict=True)

    with http.server.HTTPServer(("127.0.0.1", 0), Origin) as server:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            core = benchmark(binary)
            net = benchmark(binary, f"http://127.0.0.1:{server.server_port}/")
        finally:
            server.shutdown()
            thread.join()

    met_budget = True
    for label, (cpu, rss, exchanges), rss_limit in (("core", core, 32), ("net", net, 40)):
        rss_mb = rss / 1_000_000
        passed = cpu < CPU_BUDGET_PERCENT and rss_mb <= rss_limit
        met_budget = met_budget and passed
        print(
            f"{label}: CPU={cpu:.3f}% of one core, sampled peak RSS={rss_mb:.3f} MB, "
            f"captured HTTP exchanges={exchanges} "
            f"(budget CPU < {CPU_BUDGET_PERCENT:g}%, RSS <= {rss_limit} MB: "
            f"{'met' if passed else 'exceeded'})"
        )
    return int(args.enforce_budget and not met_budget)


if __name__ == "__main__":
    raise SystemExit(main())
