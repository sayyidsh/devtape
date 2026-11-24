# DevTape & DTP v0.1

DevTape is a local-first Rust implementation of the DevTape Protocol for recording, scrubbing, inspecting, and replaying development sessions in portable `.tape` archives. The protocol is specified in `spec/RFC-0001-dtp-v0.1.md` and `spec/dtp_v1.proto`.

Recording uses a PTY with bounded buffering and streaming redaction; archives carry events, a manifest, and an integrity hash. Sessions can be stored in SQLite, exported by privacy profile, inspected through read-only MCP tools, or viewed locally. Git snapshots use a private index, and rewind first creates a safety snapshot.

## Crates

- `dtp-codec`: tape encoding, validation, HLC, event types and replay ANSI filtering.
- `devtape-scrub`: streaming secret scrubbing.
- `devtape-pty`: PTY capture and backpressure.
- `devtape-git`: shadow snapshots, rewind and undo.
- `devtape-core`: SQLite session store and export profiles.
- `devtape-mcp`: read-only MCP stdio tools.
- `devtape-net`: opt-in loopback HTTP capture proxy.
- `devtape-ui`: loopback read-only timeline server.
- `dtp-wasm`: Rust decoding and viewer sanitization helper.
- `devtape-cli`: command-line interface.

## Usage

Run with `cargo run -p devtape-cli --`, or build and use the `devtape` binary. Examples below assume the binary is on `PATH`.

```sh
devtape doctor
devtape demo-tape --out sample.tape
devtape inspect sample.tape
devtape record --out session.tape --qos zero-stall --db sessions.db -- sh -c 'echo hello'
devtape record --net --out network.tape -- curl http://example.com/
devtape snapshot --repo . --label before-change
devtape rewind --repo . --to SNAPSHOT_ID
devtape undo-rewind --repo .
devtape sessions --db sessions.db
devtape export SESSION_ID --db sessions.db --profile full --review --out exported.tape
devtape export SESSION_ID --db sessions.db --profile diff-only --review --out diff.tape
devtape export SESSION_ID --db sessions.db --profile trace-only --review --out trace.tape
devtape view session.tape --port 0
devtape mcp --tape session.tape
printf 'Bearer example-token\n' | devtape scrub-check
```

`view` prints a loopback URL and runs until interrupted. It sanitizes dangerous terminal control sequences for display; its displayed integrity hash is that of the original archive. Archives should already have been scrubbed before sharing. `web/viewer/index.html` can display JSON locally and can decode `.tape` files when the browser supports Zstandard or a compatible `decode_and_sanitize_tape_json` JavaScript hook is supplied. Browser-native decoding does not verify the tape integrity hash. The `dtp-wasm` crate currently provides Rust functions; no browser binding or compiled WASM artifact is included.

`--net` captures plain HTTP; HTTPS CONNECT and chunked request bodies are currently unsupported. The proxy configures the child environment only and does not install a system CA.

The workspace declares Rust 1.80, but the currently locked `time` dependency requires Rust 1.88; use a compatible toolchain until that mismatch is resolved.

## Verification

```sh
CARGO_INCREMENTAL=0 cargo test --workspace
CARGO_INCREMENTAL=0 cargo clippy --workspace --all-targets -- -D warnings
```

Some integration tests require permission to bind loopback sockets.

## License

Apache-2.0. The protocol specification is open and vendor-neutral.
