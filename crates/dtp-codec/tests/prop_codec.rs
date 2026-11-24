use dtp_codec::{sanitize_ansi_for_replay, AnsiReplaySanitizer, TapeArchive};
fn next(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}
#[test]
fn randomized_stream_splits_match_whole_input() {
    let input = "é红\x1b[31mhello\x1b]52;c;secret\x1b\\\x1b]0;title\x07\x1b]1;one\x07\x1b]2;two\x1b\\\x1b[0m";
    let boundaries: Vec<_> = input
        .char_indices()
        .map(|(i, _)| i)
        .chain(std::iter::once(input.len()))
        .collect();
    let expected = sanitize_ansi_for_replay(input);
    let mut seed = 314159;
    for _ in 0..1000 {
        let mut sanitizer = AnsiReplaySanitizer::new();
        let mut output = String::new();
        let mut i = 0;
        while i < boundaries.len() - 1 {
            let j = (i + 1 + next(&mut seed) as usize % 8).min(boundaries.len() - 1);
            output.push_str(&sanitizer.push_chunk(&input[boundaries[i]..boundaries[j]]));
            i = j;
        }
        output.push_str(&sanitizer.finish());
        assert_eq!(output, expected);
        assert!(!output.contains("secret"));
    }
}
#[test]
fn malformed_bytes_never_panic() {
    let mut seed = 271828;
    for _ in 0..2000 {
        let len = next(&mut seed) as usize % 512;
        let mut bytes = vec![0; len];
        for byte in &mut bytes {
            *byte = next(&mut seed) as u8;
        }
        assert!(std::panic::catch_unwind(|| TapeArchive::decode(&bytes)).is_ok());
    }
}

#[test]
fn mutated_valid_archives_and_truncations_never_panic() {
    let original = include_bytes!("../../../spec/conformance/01_minimal_session.tape");
    let mut seed = 0x12345678;
    for i in 0..1200 {
        let mut bytes = original.to_vec();
        if i % 3 == 0 {
            bytes.truncate(next(&mut seed) as usize % bytes.len());
        } else {
            let index = next(&mut seed) as usize % bytes.len();
            bytes[index] ^= 1 << (next(&mut seed) % 8);
        }
        assert!(std::panic::catch_unwind(|| TapeArchive::decode(&bytes)).is_ok());
    }
}
