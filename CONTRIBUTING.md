# Contributing to DevTape & DTP v0.1

Thank you for contributing to **DevTape**, the reference Rust implementation of the **DevTape Protocol (DTP v0.1)**.

DevTape is designed as a **protocol first** (`spec/RFC-0001-dtp-v0.1.md` and `spec/dtp_v1.proto`). Contributions that improve cross-platform fidelity, security hardening, performance budgets, or ecosystem extensions are especially welcome.

---

## Core Engineering Rules

1. **Zero Unsafe Rust:** Every crate in the workspace enforces `#![forbid(unsafe_code)]`.
2. **Protocol First:** Keep the 7 mandatory DTP Core events minimal and stable. Put domain-specific signals behind versioned capability extensions (`ext.git.v1`, `ext.http.v1`, `ext.mcp.v1`, `ext.ci.v1`).
3. **Hard Performance Budgets:**
   - **PTY passthrough latency:** `< 2 ms` (never block terminal I/O on disk, secret scrubbing, or SQLite).
   - **Steady-state recorder CPU:** `< 2%` of one logical core.
   - **Active RAM footprint:** `~32 MB` core (`~40 MB` with `--net` enabled); `0 MB` idle for UI/MCP.
   - **Release binary size:** `< 15 MB` stripped (`opt-level = "z"`, `lto = "thin"`, `strip = true`).
4. **Defensive Consumer Parsing:** Any `.tape` reader or viewer must enforce the 1:100 decompression-bomb guard (`256 MiB` ceiling), reject path traversal (`..`, leading `/`, drive letters, null bytes), strip dangerous terminal control sequences (`OSC 52` clipboard writes, window-title overrides), and render untrusted fields without `innerHTML`.

---

## Running the Verification Suite

Before opening a pull request, run the full verification gate:

```bash
# 1. Check formatting across all 10 workspace crates
CARGO_INCREMENTAL=0 cargo fmt --all -- --check

# 2. Lint all targets with warnings treated as errors
CARGO_INCREMENTAL=0 cargo clippy --workspace --all-targets -- -D warnings

# 3. Run all 42 unit, property, conformance, and subprocess integration tests
CARGO_INCREMENTAL=0 cargo test --workspace

# 4. Verify benchmark targets compile cleanly
CARGO_INCREMENTAL=0 cargo bench --workspace --no-run

# 5. Build and verify the stripped release binary size (< 15 MB budget)
CARGO_INCREMENTAL=0 cargo build --release -p devtape-cli
node scripts/check-release-size.mjs target/release/devtape
```

### Conformance Vectors & Benchmarks

- **Golden Conformance Vectors:** Located in `spec/conformance/` and validated by `crates/dtp-codec/tests/conformance_vectors.rs`. Any change to `dtp-codec` must preserve backward compatibility with all golden `.tape` vectors.
- **Property Tests:** `crates/dtp-codec/tests/prop_codec.rs` and `crates/devtape-scrub/tests/prop_scrubber.rs` test arbitrary chunk splits, malformed headers, and truncated streams.
- **Release size:** CI checks the uncompressed, stripped Linux executable on pull requests and pushes to `main`. Release builds apply the same strict 15,000,000-byte ceiling to all four platform binaries. Use `target/release/devtape.exe` for the local size check on Windows.
- **Microbenchmarks:** Run `CARGO_INCREMENTAL=0 cargo bench --locked -p dtp-codec --bench codec_bench` and `CARGO_INCREMENTAL=0 cargo bench --locked -p devtape-scrub --bench scrub_bench`. CI records codec encode/decode time, ANSI sanitization time, fixture size, and scrubber throughput in the job summary. Timing measurements are informational on shared runners.
- **Interactive PTY latency:** After building the stripped CLI, run `python3 scripts/bench-pty.py target/release/devtape` on Linux or macOS. It compares a direct PTY against the same shell responder under `devtape record` with SQLite enabled. Both paths report p50, p95, and p99 after warmup. Added latency is recorded p95 minus direct p95. CI reports the measurements. Pass `--enforce-budget` on a controlled machine to require less than 2 ms added p95 latency.
- **Recorder CPU and memory:** On Linux, run `python3 scripts/bench-resources.py target/release/devtape`. The benchmark records 100 lines of 256 bytes per second into SQLite with and without `--net`. The network workload also sends two HTTP requests per second through the proxy to a loopback server. After warmup it samples the recorder process for ten seconds. CPU is average utilization of one logical core, and RSS is the highest scheduled sample in decimal MB. These figures exclude the recorded child and session startup and finalization. CI reports both measurements. Pass `--enforce-budget` on a controlled machine to enforce < 2% CPU and RSS ceilings of 32 MB for core and 40 MB with `--net`.
- **Sustained recording:** Run `python3 scripts/check-sustained-recording.py target/release/devtape` on Linux or macOS. The one-minute CI workload emits 20 numbered build-log lines per second. It checks that the same live session keeps committing events, the recorder propagates a nonzero command exit, and both SQLite and the final archive contain every line in order with no drops. The compressed archive must stay below 5 MB/hour at this fixture rate. Use `--seconds 3600` to measure the full hour locally. The budget applies to this fixture and the compressed archive. SQLite file size depends on the recording.

---

## Codec fuzzing

Linux CI runs two AddressSanitizer fuzz smoke tests for 30 seconds each. The tape decoder uses the checked-in conformance vectors as seeds and calls the production decoder. The ANSI replay target checks that sanitizing a stream one character at a time gives the same result as sanitizing it in one call.

With Rust nightly installed, run the same targets locally:

```bash
export CARGO_INCREMENTAL=0
cargo +nightly install cargo-fuzz --version 0.13.2 --locked

corpus=$(mktemp -d)
mkdir -p "$corpus/tape" "$corpus/ansi"
cp spec/conformance/*.tape "$corpus/tape/"
printf '\033[32mBuild café completed\033[0m\n' > "$corpus/ansi/build-log"
cargo +nightly fuzz run tape_decode "$corpus/tape" -- -max_total_time=30 -max_len=65536 -timeout=10
cargo +nightly fuzz run ansi_replay "$corpus/ansi" -- -max_total_time=30 -max_len=16384 -timeout=10
```

For a longer campaign, increase `-max_total_time` and reuse the corpus directories. Generated files under `fuzz/artifacts` and `fuzz/corpus` are local.

---

## Good First Issues & v0.2 Roadmap

Looking for a place to start? Here are high-impact areas ready for contributions:

1. **HTTPS `CONNECT` MITM Termination in `devtape-net` (`v0.2`):**
   - `devtape-net` already generates an ephemeral per-session CA certificate via `rcgen` and injects `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, and `REQUESTS_CA_BUNDLE` solely into the child PTY environment.
   - Next step: handle `CONNECT host:443` for loopback/dev targets by dynamically minting per-host leaf certificates signed by the session CA and terminating TLS with `tokio-rustls`.
2. **Chunked Request Body Capture (`Transfer-Encoding: chunked`):**
   - Extend `crates/devtape-net` to stream and decode chunked HTTP request bodies while preserving the `1 MiB` (`MAX_CAPTURED_BODY_BYTES`) truncation cap and 256-byte tail boundary guard.
3. **CI Runner Extension (`ext.ci.v1`):**
   - Detect common CI environments (GitHub Actions, GitLab CI, Buildkite) during `devtape record` and emit structured `ext.ci.v1` metadata (workflow, job, runner OS, failing test summary).
4. **Browser WASM Bindings (`crates/dtp-wasm`):**
   - Add an optional `wasm32-unknown-unknown` export target compiling `dtp_wasm::decode_and_sanitize_tape_json` into a standalone `.wasm` bundle for `web/viewer/index.html` so browsers without native `DecompressionStream('zstd')` can verify Blake3 integrity hashes client-side.
5. **Custom Scrubber Rulesets:**
   - Support user-defined redaction patterns via `.devtape/scrub.toml` while recording the custom ruleset hash in `RedactionAttestation`.

---

## Submitting Changes

- Keep pull requests focused on a single crate or capability.
- Attach a `.tape` reproduction or session trace (`devtape export <SESSION_ID> --profile diff-only --review --out pr-check.tape`) when fixing bugs or demonstrating new CLI behavior.
