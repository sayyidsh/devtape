# devtape-dtp-wasm

Decode DTP v0.1 tapes with incremental ANSI replay sanitization. Initialize once before decoding. Archives must still be treated as untrusted input.

Node.js ESM:

```js
import { readFile } from 'node:fs/promises';
import { initDtpWasm, decodeTape } from 'devtape-dtp-wasm';
await initDtpWasm();
const archive = decodeTape(await readFile('session.tape'));
```

Browser (using an ESM-aware bundler or import map):

```js
import { initDtpWasm, decodeTape } from 'devtape-dtp-wasm';
await initDtpWasm();
const archive = decodeTape(new Uint8Array(await file.arrayBuffer()));
```

Pass a URL, bytes, or compiled module to `initDtpWasm` to customize loading. The JSON-string decoder is also exported as `decode_and_sanitize_tape_json` and `decodeAndSanitizeTapeJson`.
