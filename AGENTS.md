# AGENTS.md — DevTape & DTP v0.1 Implementation Guide (for Antigravity CLI `agy`)

## 1. Mission & Product Vision
Build **DevTape**, the reference Rust implementation of **DTP v0.1 (DevTape Protocol)** — an open, local-first, vendor-neutral protocol for capturing, scrubbing, rewinding, and replaying developer and AI-agent execution sessions in a single portable `.tape` container.

**Strategic Principle:** Treat this as a **protocol first** (`spec/RFC-0001-dtp-v0.1.md` + `spec/dtp_v1.proto`), not just a standalone tool. Keep the core tiny (7 mandatory event types) and modularize domain signals (`ext.git.v1`, `ext.http.v1`, `ext.mcp.v1`, `ext.ci.v1`) as optional capabilities.

## 2. Hard Performance Budgets (Enforce in CI)
- **PTY passthrough latency:** `< 2 ms` (zero-stall hot path; never block terminal I/O on disk/scrub/SQLite).
- **Active RAM footprint:** `~32 MB` core (`~40 MB` with `--net` proxy enabled); `0 MB` idle for UI/MCP.
- **CPU overhead:** `< 2%` steady-state.
- **Compressed disk usage:** `< 5 MB / hour` (Zstd level 3 + Blake3 content-addressed deduplication).
- **Release binary size:** `< 15 MB` (`opt-level = "z"`, `lto = "thin"`, `strip = true`).

## 3. Mandatory Engineering Constraints (10 Solved Obstacles)
1. **Causal Ordering (`HLC` + Spans):** Use `HlcTimestamp` + propagate `DTP_SPAN_ID` to child processes so shell, Git, HTTP, and MCP events form a causal DAG.
2. **Deterministic Replay vs. Live Re-run:** Default replay is strictly read-only state replay; never execute shell commands from an untrusted `.tape`.
3. **State Explosion:** Respect `.gitignore`, use a temporary `GIT_INDEX_FILE` for `git write-tree`, deduplicate with `blake3`, and add FastCDC chunking for large binary files.
4. **PTY Flood / Backpressure:** Bounded non-blocking channel (`16 MB` cap). Under `QoS-0 (ZeroStall)`, drop excess bursts and emit a `DropMarker` event rather than stalling the terminal.
5. **Verifiable Secret Redaction:** Sliding-window `OverlapScrubber` (128–256B overlap) + structural placeholders (`<DTP:REDACTED:KIND:hash6>`) + `RedactionAttestation` in `TapeManifest`. Local redaction map MUST NEVER be exported.
6. **Cross-Platform Parity:** Use `portable-pty` across Linux, macOS, and Windows ConPTY; enforce CI on all 3 OSes.
7. **Zero-Root Local HTTPS Proxy (`--net`):** Generate ephemeral session CA via `rcgen` and inject `SSL_CERT_FILE` / `NODE_EXTRA_CA_CERTS` / `REQUESTS_CA_BUNDLE` into the child PTY only.
8. **SQLite Concurrency:** Use `PRAGMA journal_mode=WAL` with a single-writer actor batching writes every `250-500 ms`.
9. **Safe Rewind:** Always create an automatic `pre-rewind` safety snapshot before modifying the working tree (`devtape undo-rewind`).
10. **Malicious `.tape` Defense:** Enforce `1:100` max decompression ratio (`DEFAULT_MAX_UNCOMPRESSED_BYTES = 256 MiB`), reject path traversal (`..`, absolute paths, drive letters), and strip dangerous ANSI sequences (e.g., `OSC 52`).

## 4. Current Workspace State (Already Implemented)
- `spec/RFC-0001-dtp-v0.1.md` — Full DTP v0.1 normative spec.
- `spec/dtp_v1.proto` — Canonical Protobuf v3 schema.
- `crates/dtp-codec/` — `HlcTimestamp`, `EventEnvelope`, `CoreEvent`, `TapeArchive` encode/decode with 1:100 bomb guard, path-traversal check, and unit tests.
- `crates/devtape-scrub/` — `Scrubber` and `OverlapScrubber` with split-chunk unit tests.
- `crates/devtape-cli/` — Working CLI with `demo-tape`, `inspect`, and `scrub-check`.
- `docs/` — Full planning reports from our architecture sessions (HTML reference docs).

## 5. Immediate Next Implementation Tasks for `agy`
1. **Verify baseline:** Run `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`. Fix any warnings or dependency issues.
2. **Build `crates/devtape-pty`:** Implement `devtape record` using `portable-pty` + `tokio` with zero-stall passthrough, bounded channel backpressure (`DropMarker`), and `OverlapScrubber` integration.
3. **Build `crates/devtape-git`:** Implement non-destructive shadow snapshots using temporary `GIT_INDEX_FILE` + `git write-tree`, plus `devtape rewind` with automatic pre-rewind backup snapshot.
4. **Build `crates/devtape-core` SQLite WAL store:** Add single-writer batched event persistence and `devtape export --profile <full|diff-only|trace-only> --review`.
5. **Phase 3 & 4:** Add `devtape-net` (`--net` loopback proxy), `devtape-mcp` (stdio MCP server for AI coding agents), embedded local UI (`rust-embed`), and WASM `.tape` viewer.
