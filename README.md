# DevTape & DTP v0.1 (Open Execution & Context Replay Protocol)

**DevTape** is the reference Rust implementation of the **DevTape Protocol (DTP v0.1)** — an open, local-first protocol for capturing, scrubbing, rewinding, and replaying developer and AI-agent execution sessions in a single portable `.tape` container.

## Repository Layout

- `spec/RFC-0001-dtp-v0.1.md` — Normative DTP v0.1 protocol specification (HLC causality, `.tape` container, security rules, export profiles).
- `spec/dtp_v1.proto` — Canonical Protocol Buffers v3 wire schema with fixed field tags.
- `crates/dtp-codec/` — Core Rust codec (HLC clock, event envelope, `.tape` container reader/writer with 1:100 decompression bomb guard).
- `crates/devtape-scrub/` — Streaming secret scrubber with sliding-window overlap and deterministic structural placeholders.
- `crates/devtape-cli/` — Reference CLI (`devtape`) wired to `dtp-codec` and `devtape-scrub`.
- `.github/workflows/ci.yml` — Cross-platform CI matrix (Linux, macOS, Windows).

## Quickstart

Requires Rust 1.80+:

```bash
# Run all unit tests across the workspace (HLC, .tape codec, bomb guard, sliding-window scrubber)
cargo test --workspace

# Create a sample DTP v0.1 .tape file and inspect its manifest & events
cargo run -p devtape-cli -- demo-tape --out sample.tape
cargo run -p devtape-cli -- inspect sample.tape

# Test the sliding-window secret scrubber on a file or stdin
echo "export OPENAI_API_KEY=sk-proj-abc12345678901234567890" | cargo run -p devtape-cli -- scrub-check
```

## License

Dual-licensed / Apache-2.0. The protocol specification in `spec/` is open and vendor-neutral.
