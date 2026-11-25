#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
export CC_wasm32_unknown_unknown="${CC_wasm32_unknown_unknown:-clang}"
export AR_wasm32_unknown_unknown="${AR_wasm32_unknown_unknown:-llvm-ar}"
cargo build --locked --release -p dtp-wasm --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir packages/dtp-wasm/pkg --out-name dtp_wasm target/wasm32-unknown-unknown/release/dtp_wasm.wasm
printf '{"type":"module"}\n' > packages/dtp-wasm/pkg/package.json
