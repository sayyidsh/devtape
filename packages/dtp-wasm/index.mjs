import init, { decode_and_sanitize_tape_json as decode } from './pkg/dtp_wasm.js';

export async function initDtpWasm(input) {
  if (input === undefined && typeof process !== 'undefined' && process.versions?.node) {
    const { readFile } = await import('node:fs/promises');
    const { fileURLToPath } = await import('node:url');
    input = await readFile(fileURLToPath(new URL('./pkg/dtp_wasm_bg.wasm', import.meta.url)));
  }
  return input === undefined ? init() : init({ module_or_path: input });
}
export const decode_and_sanitize_tape_json = decode;
export const decodeAndSanitizeTapeJson = decode;
export function decodeTape(bytes) { return JSON.parse(decode(bytes)); }
