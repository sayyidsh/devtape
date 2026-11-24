// Execute the actual wasm-bindgen web bundle in Node (no browser decompression).
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { zstdCompressSync } from 'node:zlib';

const modulePath = resolve(process.argv[2] || 'web/viewer/pkg/dtp_wasm.js');
const { default: init, decode_and_sanitize_tape_json: decode } = await import(pathToFileURL(modulePath));
const wasmBytes = readFileSync(join(dirname(modulePath), 'dtp_wasm_bg.wasm'));
const compiled = new WebAssembly.Module(wasmBytes);
assert.equal(WebAssembly.Module.imports(compiled).some(i => i.module === 'env' || i.module.startsWith('wasi')), false, 'Zstandard must be linked, not imported from a missing C runtime');
await init({ module_or_path: wasmBytes });
let passed = 0;
for (const vector of JSON.parse(readFileSync('spec/conformance/manifest.json', 'utf8'))) {
  const bytes = readFileSync(join('spec/conformance', vector.filename));
  if (vector.expected === 'valid') {
    const archive = JSON.parse(decode(bytes));
    assert.ok(archive.manifest.session_id);
  } else {
    assert.throws(() => decode(bytes), undefined, vector.filename);
  }
  passed++;
}
const fixture = readFileSync('target/browser-test.tape');
const sanitized = JSON.parse(decode(fixture));
assert.equal(sanitized.events[0].event.label, 'test');
assert.equal(sanitized.events.filter(e => e.event.channel === 'stdout').map(e => e.event.data).join(''), 'helloworld');
assert.equal(sanitized.events[2].event.data, 'errorsafe');
assert.ok(!JSON.stringify(sanitized).includes('SECRET'));
passed++;
// Recompress JSON to exercise validation *inside* the compiled decoder.
const container = data => {
  const json = Buffer.from(JSON.stringify(data));
  const header = Buffer.alloc(16);
  header.write('DTAP01'); header.writeUInt16BE(1, 6); header.writeBigUInt64BE(BigInt(json.length), 8);
  return Buffer.concat([header, zstdCompressSync(json)]);
};
for (const [mutate, message] of [
  [a => { a.manifest.redaction.local_map_excluded = false; }, /local redaction map/],
  [a => { a.events.find(e => e.event.type === 'state_snapshot').event.changed_files = ['../escape']; }, /unsafe path/],
  [a => { a.integrity_blake3 = '0'.repeat(64); }, /integrity hash mismatch/],
]) {
  const data = structuredClone(sanitized); mutate(data);
  assert.throws(() => decode(container(data)), message); passed++;
}
for (const length of [1n << 32n, (1n << 64n) - 1n]) {
  const bad = Buffer.from(fixture); bad.writeBigUInt64BE(length, 8);
  assert.throws(() => decode(bad), /decompression bomb/); passed++;
}
console.log(`WASM bundle: ${passed} checks passed (10 valid vectors, 6 invalid vectors, split ANSI, map/path/hash, 64-bit headers)`);
