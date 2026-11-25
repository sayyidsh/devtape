import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { initDtpWasm, decodeTape, decode_and_sanitize_tape_json } from './index.mjs';
const dir = new URL('../../spec/conformance/', import.meta.url);
const manifest = JSON.parse(await readFile(new URL('manifest.json', dir), 'utf8'));
await initDtpWasm();
assert.equal(manifest.length, 16);
let valid = 0, invalid = 0;
for (const vector of manifest) {
  const bytes = await readFile(new URL(vector.filename, dir));
  if (vector.expected === 'valid') {
    assert.ok(decodeTape(bytes).manifest.session_id, vector.filename);
    valid++;
  } else {
    assert.throws(() => decode_and_sanitize_tape_json(bytes), undefined, vector.filename);
    invalid++;
  }
}
assert.equal(valid, 10); assert.equal(invalid, 6);
const wrapped = await readFile(new URL('01_minimal_session.tape', dir));
wrapped.writeBigUInt64BE(1n << 32n, 8);
assert.throws(() => decode_and_sanitize_tape_json(wrapped));
console.log(`WASM conformance: ${valid} valid, ${invalid} invalid, 1 64-bit header wrap-around passed`);
