# Security Policy

DevTape is designed to capture and share developer and AI-agent execution sessions safely across public issue trackers, pull requests, and CI logs. Security and verifiable privacy are foundational requirements of the **DevTape Protocol (DTP v0.1)**.

---

## Supported Versions

| Version | Protocol Spec | Supported |
| ------- | ------------- | --------- |
| `0.1.x` | DTP v0.1 (`DTAP01`) | Yes |

---

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

If you discover a vulnerability in DevTape or the DTP v0.1 specification (such as a secret-scrubber bypass, decompression bomb bypass, path traversal during snapshot rewind, ANSI terminal escape injection, or UI XSS):

1. Open a private **GitHub Security Advisory** on the repository (`Security` -> `Report a vulnerability`), or contact the maintainers privately.
2. Include a minimal reproduction (never include real production credentials) and the affected crate (`dtp-codec`, `devtape-scrub`, `devtape-pty`, `devtape-git`, `devtape-core`, `devtape-net`, `devtape-mcp`, `devtape-ui`, or `dtp-wasm`).
3. We aim to acknowledge reports within **48 hours** and ship a patched release and advisory within **7 days**.

---

## DTP v0.1 Security & Privacy Guarantees

### 1. Memory Safety
- Every crate in the DevTape workspace compiles with `#![forbid(unsafe_code)]`.

### 2. Verifiable Secret Redaction (`devtape-scrub`)
- **Sliding-Window Overlap:** `OverlapScrubber` maintains a 128-byte sliding window with token-boundary retention (bounded to 4x overlap) so secrets split across arbitrary PTY read chunks or network reads are caught before persistence.
- **Deterministic Structural Placeholders:** Matched credentials (`AWS_KEY`, `GITHUB_TOKEN`, `API_KEY`, `BEARER`, `JWT`) are replaced with `<DTP:REDACTED:KIND:hash6>` (using a 6-hex prefix of the Blake3 digest).
- **Cutoff Boundary Protection:** When `devtape-net` truncates HTTP bodies larger than `1 MiB`, it trims the trailing 256 bytes prior to scrubbing so a secret straddling the 1 MiB cutoff boundary cannot leak as an unredacted prefix.
- **No Exported Secret Map:** `TapeArchive::new`, `TapeArchive::encode`, and `TapeArchive::decode` reject any archive where `manifest.redaction.local_map_excluded` is `false`.
- **Export Privacy Profiles (`devtape-core`):**
  - `full`: Reassembles streams per channel, re-scrubs all text and JSON fields, and excludes any local secret map.
  - `diff-only`: Strips all terminal `StreamChunk` I/O, retaining only session lifecycle, command spans, `StateSnapshot`, and `ext.git.v1` metadata.
  - `trace-only`: Enterprise compliance mode stripping both `StreamChunk` and `StateSnapshot`/`ext.*` payloads.

### 3. Defensive Consumer Rules (`dtp-codec`, `devtape-ui`, `devtape-mcp`)
- **Decompression Bomb Guard:** Readers enforce a maximum `1:100` compressed-to-uncompressed expansion ratio and a hard ceiling of `256 MiB` (`DEFAULT_MAX_UNCOMPRESSED_BYTES`), reading through a bounded `Read::take` stream before JSON deserialization.
- **Blake3 Integrity Verification:** Every `.tape` container verifies its canonical `integrity_blake3` digest on decode and rejects tampered archives with `CodecError::IntegrityMismatch`.
- **Path Traversal & Rewind Guard (`dtp-codec` & `devtape-git`):**
  - Snapshot paths containing `..`, leading `/` or `\`, Windows drive letters (`C:`), or null bytes are rejected.
  - `devtape rewind` always creates an automatic `pre-rewind` safety snapshot (`devtape undo-rewind`), refuses to traverse symlinked parent directories, refuses to overwrite unmanaged files or directories, and operates via an isolated `GIT_INDEX_FILE`.
  - Pre-rewind safety data stores no-follow raw working-tree bytes, file types, and supported permissions in a private manifest independent of Git clean/smudge attributes. Undo verifies the complete backup before mutation and fails closed if safety data is unavailable or corrupt.
- **Terminal Escape Sanitization:** `AnsiReplaySanitizer` strips `OSC 52` clipboard-write sequences and window-title manipulation (`OSC 0`, `OSC 1`, `OSC 2`) across split chunks while preserving standard SGR colors.
- **Read-Only Replay & Local UI Hardening:**
  - `devtape inspect`, `devtape view`, and `devtape mcp` are strictly read-only and never execute recorded shell commands.
  - `devtape-ui` binds exclusively to `127.0.0.1`, verifies loopback peer addresses, validates the `Host: 127.0.0.1` header against DNS rebinding, sends a strict `Content-Security-Policy`, and renders all tape content via DOM `textContent` (zero `innerHTML`).
- **Zero-Root Child-Only Network Proxy (`devtape-net`):**
  - `devtape record --net` binds strictly to `127.0.0.1:0`, generates an ephemeral session CA with `0600` permissions, and injects `HTTP_PROXY` / `HTTPS_PROXY` / `SSL_CERT_FILE` / `NODE_EXTRA_CA_CERTS` / `REQUESTS_CA_BUNDLE` solely into the child PTY process without modifying the host environment or system trust store.
