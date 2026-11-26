#![no_main]
#![forbid(unsafe_code)]

use dtp_codec::{sanitize_ansi_for_replay, AnsiReplaySanitizer};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let text = String::from_utf8_lossy(bytes);
    let whole = sanitize_ansi_for_replay(&text);
    let mut sanitizer = AnsiReplaySanitizer::new();
    let mut streamed = String::new();

    // Try a boundary at every character, including within escape sequences.
    for (start, character) in text.char_indices() {
        streamed.push_str(&sanitizer.push_chunk(&text[start..start + character.len_utf8()]));
    }
    streamed.push_str(&sanitizer.finish());
    assert_eq!(streamed, whole);
});
