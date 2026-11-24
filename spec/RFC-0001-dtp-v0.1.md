# RFC-0001: DevTape Protocol (DTP) v0.1 Specification

- **Status:** Draft (v0.1)
- **License:** Apache-2.0 / CC-BY-4.0
- **Scope:** Wire Event Envelope, `.tape` Container Format, Redaction Attestation, and Consumer Safety Rules

## 1. Design Goals

DTP defines a vendor-neutral, local-first format for capturing and replaying software development and AI coding-agent sessions across terminals, IDEs, CI runners, and autonomous agents.

1. **Minimal Core, Modular Extensions:** Any implementation supporting the 7 core event types is DTP Core compliant. Domain signals (Git, HTTP, MCP, CI) are negotiated as optional capability extensions.
2. **Causal Ordering Across Concurrent Producers:** Every event carries a Hybrid Logical Clock (HLC) timestamp and an optional `parent_span_id` (propagated to child processes via `DTP_SPAN_ID`).
3. **Zero-Stall Interactive Capture:** Producers MUST declare a QoS level: `QoS-0 (Zero-Stall)` allows dropping excess bursts with a mandatory `DropMarker` event; `QoS-1 (Lossless)` is intended for CI and auditing.
4. **Verifiable Privacy by Construction:** Exported `.tape` files MUST NOT include raw local secret-mapping tables and MUST include a `redaction_attestation` block.
5. **Defensive Consumer Parsing:** Readers MUST enforce strict resource bounds against malicious `.tape` files shared on public issue trackers.

## 2. Hybrid Logical Clock (HLC) & Causal Spans

Every `EventEnvelope` includes:
- `seq` (`uint64`): Strictly increasing sequence number within a session.
- `hlc` (`physical_ms: uint64`, `logical: uint32`, `node_id: uint32`): Guarantees total causal ordering even when wall-clock timestamps collide or drift.
- `span_id` (`string`, 16-hex) & `parent_span_id` (`optional string`): Links shell commands, file mutations, local HTTP requests, and AI agent tool calls into a Causal DAG.

## 3. Core Event Types (DTP Core)

1. `SessionStart`: Environment metadata (`os`, `arch`, `shell`, sanitized `cwd`, `qos_mode`, `export_profile`, declared `extensions`).
2. `SpanStart`: Begins a command, agent step, or sub-operation.
3. `SpanEnd`: Terminates a span with `exit_code` or status.
4. `StreamChunk`: Captured `stdin`, `stdout`, or `stderr` bytes (already scrubbed).
5. `StateSnapshot`: Reference to a content-addressed workspace tree digest (`blake3`), never raw absolute host paths.
6. `DropMarker`: Emitted under `QoS-0` backpressure recording `bytes_dropped` and reason.
7. `SessionEnd`: Final summary, duration, and integrity root hash.

### Optional Capability Extensions
- `ext.git.v1`: Shadow tree hashes, branch/HEAD metadata, and file diffs.
- `ext.http.v1`: Loopback HTTP/gRPC request/response metadata and latency.
- `ext.mcp.v1`: AI coding-agent MCP tool calls, arguments, and results.
- `ext.ci.v1`: CI job metadata, runner labels, and failing test summaries.

**Unknown Event Preservation:** Consumers encountering an unrecognized extension event MUST NOT fail; they MUST preserve or skip it gracefully.

## 4. `.tape` Container Format (`DTAP01`)

A `.tape` file is a binary stream structured as:
1. **Magic Header (6 bytes):** ASCII `DTAP01`.
2. **Format Version (2 bytes, big-endian `u16`):** `0x0001`.
3. **Payload Length (8 bytes, big-endian `u64`):** Uncompressed JSON/CBOR payload size declared for pre-allocation checks.
4. **Compressed Payload (Zstd):** Contains `TapeManifest` + ordered `EventEnvelope[]` + Blake3-indexed deduplicated blobs.

## 5. Export Privacy Profiles

- `full`: Complete session (sanitized of secrets and home-directory usernames), suited for open-source bug reports.
- `diff_only`: Only file diffs, failing commands, and exit codes.
- `trace_only`: Command timeline, span DAG, and stack traces with zero source-code blobs (enterprise compliance mode).

## 6. Mandatory Consumer Security Rules

Every DTP-compliant reader MUST enforce:
1. **Decompression Bomb Guard:** Reject any `.tape` whose decompressed size exceeds `100x` the compressed size OR exceeds a configurable hard ceiling (default `256 MiB`).
2. **Path Traversal Rejection:** Reject any snapshot entry containing `..`, leading `/`, drive letters (`C:\`), or null bytes.
3. **ANSI Sanitization:** Viewers MUST strip dangerous terminal control sequences (e.g., `OSC 52` clipboard write, window title manipulation) during replay.
4. **Read-Only Replay Default:** Opening an external `.tape` MUST NEVER execute recorded shell commands automatically.
