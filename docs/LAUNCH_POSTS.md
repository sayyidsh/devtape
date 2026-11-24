# DevTape & DTP v0.1.0 — Open-Source Launch Kit

- **GitHub Repository:** `https://github.com/sayyidsh/devtape`
- **Release Tag:** `v0.1.0` (`https://github.com/sayyidsh/devtape/releases/tag/v0.1.0`)
- **Protocol Spec:** `spec/RFC-0001-dtp-v0.1.md` & `spec/dtp_v1.proto`
- **Workspace:** 10 Rust crates (`#![forbid(unsafe_code)]`), 42/42 tests passing, `3.94 MiB` (`4,134,544` bytes) stripped binary

---

## 1. GitHub Launch & Day-1 `good-first-issue` Seed Commands

```bash
# 1. Create public GitHub repository and push main + v0.1.0 tag
gh repo create devtape --public --source=. --remote=origin --push
git push origin v0.1.0
```

### Seed Issues (`good-first-issue`)

1. **`feat(devtape-net): Opt-in loopback HTTPS CONNECT TLS termination with ephemeral session CA (v0.2)`**
   - Labels: `enhancement`, `good first issue`
   - Scope: `crates/devtape-net` already generates an ephemeral per-session CA certificate via `rcgen` and injects `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, and `REQUESTS_CA_BUNDLE` solely into the child PTY environment. Implement `CONNECT host:port` handling for loopback/dev targets by dynamically minting per-host leaf certificates signed by the session CA and terminating TLS with `tokio-rustls`.
2. **`feat(devtape-net): Support Transfer-Encoding: chunked request bodies with 1 MiB truncation guard`**
   - Labels: `enhancement`, `good first issue`
   - Scope: Extend `crates/devtape-net` to decode and forward `Transfer-Encoding: chunked` request bodies while preserving the `1 MiB` (`MAX_CAPTURED_BODY_BYTES`) truncation cap and 256-byte trailing boundary secret guard.
3. **`feat(ext.ci.v1): Emit structured CI environment metadata during devtape record`**
   - Labels: `enhancement`, `good first issue`
   - Scope: Detect GitHub Actions, GitLab CI, and Buildkite environment variables during `devtape record` and emit an optional `ext.ci.v1` extension event containing workflow/job identifiers, runner OS/arch, and failing command summaries.
4. **`feat(dtp-wasm): Compile standalone .wasm decoder bundle for web/viewer/index.html`**
   - Labels: `enhancement`, `good first issue`
   - Scope: Add a `wasm32-unknown-unknown` build script/target wrapping `dtp_wasm::decode_and_sanitize_tape_json` so `web/viewer/index.html` can decode `.tape` files and verify Blake3 integrity hashes in browsers without native `DecompressionStream('zstd')`.

---

## 2. Show HN Post (Hacker News)

- **Submit URL:** `https://news.ycombinator.com/submit`
- **Title:** `Show HN: DevTape – Open protocol and 3.9MB Rust CLI for recording dev/AI sessions (.tape)`

### Text / First Comment

```text
Hi HN,

We built DevTape, an open, local-first protocol (DTP v0.1) and reference Rust CLI for capturing, scrubbing, rewinding, and replaying terminal and AI coding-agent sessions in a single portable `.tape` file.

When a build fails in CI, a bug happens locally, or an AI coding agent goes off the rails across 15 tool calls and shell commands, we usually still debug by pasting truncated terminal logs into GitHub issues. Existing terminal recorders capture raw stdout characters, but miss causal structure (which command caused which file diff or loopback HTTP call), leak secrets if a token is split across two PTY read chunks, or stall the terminal when a command floods stdout.

We designed DTP v0.1 as a protocol first (`spec/RFC-0001-dtp-v0.1.md` + `spec/dtp_v1.proto`) and built the reference implementation across 10 Rust crates (`#![forbid(unsafe_code)]` in every crate):

1. Zero-stall PTY hot path (< 2 ms passthrough): A dedicated OS reader thread forwards raw bytes straight to the host terminal first, then enqueues a non-blocking copy into a 16 MiB byte-bounded queue. Under `QoS-0 (ZeroStall)`, a `yes` flood never freezes your terminal—excess bursts are dropped immediately and recorded as a normative `DropMarker` event.
2. Sliding-window secret redaction (`OverlapScrubber`): Retains a 128-byte sliding window and token boundary across adjacent PTY chunks so secrets (`sk-proj-...`, `AKIA...`, `ghp_...`, `Bearer ...`, JWTs) split across read boundaries are still caught and replaced with deterministic structural placeholders (`<DTP:REDACTED:KIND:hash6>`). Exported `.tape` files carry a `RedactionAttestation` and reject any archive with a local secret map attached.
3. Non-destructive Git shadow snapshots & safe rewind (`ext.git.v1`): Uses a temporary `GIT_INDEX_FILE` + `git write-tree` + FastCDC content-defined chunking (16–256 KiB, Blake3 + Zstd CAS) so snapshots never touch your real `.git/index` or `git status`. `devtape rewind` automatically takes a `pre-rewind` backup (`devtape undo-rewind`) and refuses to overwrite unmanaged/ignored collisions.
4. Child-only loopback HTTP capture (`devtape record --net`): Binds an opt-in proxy to `127.0.0.1:0`, injects `HTTP_PROXY` and an ephemeral per-session CA cert only into the child PTY (zero root privileges, zero system trust store changes), scrubs headers/bodies, and truncates bodies > 1 MiB (trimming the trailing 256B before scrubbing so a secret straddling the 1 MiB cutoff cannot leak).
5. Native MCP server for AI agents (`devtape mcp --tape bug.tape`): Exposes 4 read-only JSON-RPC 2.0 tools over stdio (`tape_summary`, `tape_get_failures`, `tape_get_diff`, `tape_search_logs`) so Claude Code, Codex, or any MCP client can inspect a failing `.tape` without re-running untrusted commands.
6. Defensive `.tape` consumers (`devtape view`): Enforces a 1:100 decompression bomb guard (256 MiB ceiling), Blake3 integrity verification, path-traversal rejection, stateful `OSC 52` clipboard-write stripping across split chunks, and a local loopback timeline viewer (`127.0.0.1` + `Host` header DNS-rebinding check + strict CSP + zero `innerHTML`).

The entire CLI—including bundled SQLite (WAL single-writer actor), portable-pty, Zstd, Blake3, FastCDC, MCP stdio server, loopback HTTP proxy, and embedded Timeline UI—compiles to a single 3.94 MiB stripped binary.

Quick try:
  devtape record --out session.tape -- cargo test
  devtape export <SESSION_ID> --profile diff-only --review --out bug-report.tape
  devtape view bug-report.tape

We'd love feedback on the DTP v0.1 spec (`spec/RFC-0001-dtp-v0.1.md`), the threat model in `SECURITY.md`, and edge cases we should tackle for v0.2 (such as opt-in loopback HTTPS CONNECT termination and `ext.ci.v1`).

Repo: https://github.com/sayyidsh/devtape
```

---

## 3. Reddit Post (`r/rust`)

- **Submit URL:** `https://www.reddit.com/r/rust/submit`
- **Title:** `DevTape (DTP v0.1): A 3.94 MiB, 10-crate #![forbid(unsafe_code)] workspace for causal terminal, Git, HTTP & AI-agent session recording (.tape)`

### Body

```markdown
We just tagged `v0.1.0` of **DevTape**, the reference Rust implementation of the **DevTape Protocol (DTP v0.1)** — an open, local-first container format (`.tape`) and CLI for recording, scrubbing, rewinding, and inspecting developer and AI-agent sessions.

### Architecture & Rust Crates (10 crates, `#![forbid(unsafe_code)]`)

* **`dtp-codec`**: Hybrid Logical Clock (`HlcTimestamp`) for total causal ordering across concurrent producers (PTY stdout/stdin, Git snapshots, loopback HTTP proxy), `DTAP01` binary framing (Zstd level 3 + Blake3 integrity hash), 1:100 decompression-bomb guard via `Read::take`, path-traversal validator, and a stateful `AnsiReplaySanitizer` that strips `OSC 52` clipboard writes and window-title sequences even when split across UTF-8 chunk boundaries.
* **`devtape-scrub`**: Streaming `OverlapScrubber` with a 128-byte sliding window and word-boundary retention (bounded to `4x` overlap so delimiter-free minified/base64 streams cannot grow the tail buffer unboundedly). Replaces secrets with `<DTP:REDACTED:KIND:hash6>`.
* **`devtape-pty`**: Cross-platform PTY recorder (`portable-pty` + `tokio`) separating the synchronous OS reader thread (`< 2 ms` passthrough budget) from the async collector via a byte-bounded `16 MiB` queue (`QoS-0 ZeroStall` emits `DropMarker` events under flood bursts; `QoS-1 Lossless` uses a `Condvar` byte budget).
* **`devtape-git`**: Non-destructive shadow snapshots using an isolated temporary `GIT_INDEX_FILE` + `git write-tree` pinned under `refs/devtape/snapshots/<id>` (preventing `git gc` pruning), plus a Gear-hash `FastCdcChunker` (16 KiB min / 64 KiB avg / 256 KiB max) writing Zstd-compressed chunks into a local Blake3 CAS. Includes `devtape rewind` and `devtape undo-rewind`.
* **`devtape-core`**: Single-writer SQLite WAL actor (`PRAGMA journal_mode=WAL`, 300 ms transactional batching) and privacy-profile exporter (`full`, `diff-only`, `trace-only` + `--review` JSON audit report). Reassembles channels on export to catch any secrets split across event boundaries.
* **`devtape-net`**: Opt-in `127.0.0.1:0` HTTP capture proxy (`--net`) with ephemeral `rcgen` session CA generation (`0600` temp PEM), child-only PTY env injection (`HTTP_PROXY`, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`), 1 MiB body truncation with a 256-byte trailing boundary trim before scrubbing, and `ext.http.v1` event emission.
* **`devtape-mcp`**: Zero-dependency JSON-RPC 2.0 MCP stdio server (supporting both newline-delimited and `Content-Length` framing) exposing `tape_summary`, `tape_get_failures`, `tape_get_diff`, and `tape_search_logs`.
* **`devtape-ui` & `dtp-wasm`**: Embedded single-page Timeline viewer (`devtape view <path.tape>`) bound strictly to `127.0.0.1` with `Host` header validation, strict CSP, and pure `textContent` DOM rendering.

### Release Binary Footprint
With `opt-level = "z"`, `lto = "thin"`, `codegen-units = 1`, and `strip = true` (even with `rusqlite` bundled SQLite + `zstd` + `blake3` + `rcgen` + `tokio`), the final binary is **3.94 MiB (`4,134,544` bytes)** — well under our 15 MiB CI budget.

All 42 unit, property, golden conformance vector, and subprocess integration tests run cleanly via `cargo test --workspace`. Contributions and feedback on the RFC (`spec/RFC-0001-dtp-v0.1.md`) are very welcome!

GitHub: https://github.com/sayyidsh/devtape
```

---

## 4. X (Twitter) Launch Thread

### Post 1/5
```text
Introducing DevTape (DTP v0.1): an open, local-first protocol and 3.94 MiB Rust CLI for capturing, scrubbing, rewinding, and replaying developer & AI-agent execution sessions in a single portable `.tape` file.

10 crates. `#![forbid(unsafe_code)]`. Zero cloud required. 🧵👇
```

### Post 2/5
```text
Why another recorder?
Terminal asciicasts only capture screen characters. When a build fails or an AI agent breaks a repo, you need causal structure:
- Which command (`DTP_SPAN_ID`) triggered which file diff (`ext.git.v1`) or localhost HTTP call (`ext.http.v1`)?
- Ordered by Hybrid Logical Clocks (HLC).
```

### Post 3/5
```text
10 engineering obstacles we solved in v0.1.0:
⚡ < 2ms zero-stall PTY hot path (16 MiB bounded channel + QoS-0 `DropMarker` on stdout floods)
🔒 128B sliding-window `OverlapScrubber` (catches secrets split across PTY/TCP read chunks)
🌳 Non-destructive Git shadow snapshots (`GIT_INDEX_FILE` + FastCDC CAS + safe `rewind` / `undo-rewind`)
```

### Post 4/5
```text
Built for AI coding agents & public bug reports:
🤖 `devtape mcp --tape bug.tape` runs a read-only stdio MCP server (`tape_summary`, `tape_get_failures`, `tape_get_diff`, `tape_search_logs`) so Claude Code or Codex can debug a `.tape` in one tool call.
🛡️ `devtape export --profile diff-only --review` strips terminal streams for safe GitHub issue sharing.
```

### Post 5/5
```text
Defensive by default:
- 1:100 decompression bomb guard (256 MiB cap)
- Blake3 archive integrity verification
- Stateful `OSC 52` clipboard-hijack stripping across split chunks
- `devtape view` local timeline UI (`127.0.0.1` + DNS-rebinding guard + CSP + zero `innerHTML`)

All in a single 3.94 MiB stripped Rust binary.

GitHub (Apache-2.0): https://github.com/sayyidsh/devtape
```

---

## 5. LinkedIn Launch Post

```text
We just tagged v0.1.0 of DevTape — an open, local-first protocol (DTP v0.1) and reference Rust implementation for capturing, scrubbing, rewinding, and replaying software development and AI coding-agent sessions in a single portable `.tape` container.

GitHub: https://github.com/sayyidsh/devtape

As AI coding agents (Claude Code, Codex, custom MCP pipelines) take on multi-step debugging and refactoring, reproducing what happened when a session fails has become a major bottleneck. Raw terminal logs lose causal relationships between shell commands, working-tree mutations, and local API calls—and sharing raw logs risks leaking credentials.

Key highlights of DevTape & DTP v0.1:
• Protocol-First Design (`RFC-0001`): 7 minimal core events ordered by Hybrid Logical Clocks (HLC) + modular extensions (`ext.git.v1`, `ext.http.v1`, `ext.mcp.v1`).
• Zero-Stall Terminal Capture: Dedicated PTY hot path (< 2 ms passthrough latency) with a 16 MiB byte-bounded backpressure queue that emits `DropMarker` events rather than freezing your terminal during output floods.
• Verifiable Secret Redaction: Sliding-window `OverlapScrubber` catches credentials split across PTY or HTTP chunk boundaries, replaces them with deterministic `<DTP:REDACTED:KIND:hash6>` tokens, and supports `full`, `diff-only`, and enterprise `trace-only` export profiles.
• Safe Git Rewind: Shadow working-tree snapshots via an isolated `GIT_INDEX_FILE` and FastCDC content-addressed storage—never polluting `.git/index` or `git status`, with automatic `pre-rewind` safety backups.
• Native MCP Server & Local Timeline UI: Inspect failures directly from AI agents via `devtape mcp --tape session.tape`, or scrub through the timeline locally with `devtape view session.tape`.

The entire 10-crate Rust workspace enforces `#![forbid(unsafe_code)]`, passes 42 unit, property, conformance, and integration tests, and compiles into a single 3.94 MiB stripped binary.
```
