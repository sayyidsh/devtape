export type DtpWasmInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;
export function initDtpWasm(input?: DtpWasmInput | Promise<DtpWasmInput>): Promise<WebAssembly.Exports>;
export function decode_and_sanitize_tape_json(bytes: Uint8Array): string;
export const decodeAndSanitizeTapeJson: typeof decode_and_sanitize_tape_json;
export function decodeTape(bytes: Uint8Array): { manifest: { session_id: string; [key: string]: unknown }; [key: string]: unknown };
