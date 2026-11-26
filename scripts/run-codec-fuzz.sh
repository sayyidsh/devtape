#!/usr/bin/env bash
set -euo pipefail

duration=${1:-30}
seed=${2:-1}
if [[ ! "$duration" =~ ^[1-9][0-9]*$ || ! "$seed" =~ ^[1-9][0-9]*$ ]]; then
  echo "Usage: bash scripts/run-codec-fuzz.sh [seconds-per-target] [seed]" >&2
  exit 2
fi

export CARGO_INCREMENTAL=0
corpus=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/devtape-fuzz.XXXXXX")
trap 'rm -rf "$corpus"' EXIT
mkdir -p "$corpus/tape" "$corpus/ansi"
cp spec/conformance/*.tape "$corpus/tape/"
printf '\033[32mBuild café completed\033[0m\n' > "$corpus/ansi/build-log"

cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1 >/dev/null
cargo fuzz run tape_decode "$corpus/tape" -- \
  "-seed=$seed" "-max_total_time=$duration" -max_len=65536 -timeout=10 -print_final_stats=1
cargo fuzz run ansi_replay "$corpus/ansi" -- \
  "-seed=$seed" "-max_total_time=$duration" -max_len=16384 -timeout=10 -print_final_stats=1
