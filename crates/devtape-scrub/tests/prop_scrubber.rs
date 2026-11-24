use devtape_scrub::{OverlapScrubber, Scrubber};
fn next(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}
#[test]
fn randomized_chunk_splits_match_full_scrub() {
    let secrets = [
        "sk-proj-1234567890abcdefghijklmno",
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_1234567890abcdefghijklmnop",
        "Bearer abcdefghijklmnopqrstuvwxyz012345",
        "eyJabcdefghijklm.eyJabcdefghijklm.abcdefghijklm",
    ];
    let mut seed = 987654321;
    for n in 0..600 {
        let secret = secrets[n % secrets.len()];
        let input = format!(
            "{}é {secret} end {}",
            "a".repeat(next(&mut seed) as usize % 180),
            "文".repeat(next(&mut seed) as usize % 30)
        );
        let expected = Scrubber::new().scrub_str(&input);
        let boundaries: Vec<_> = input
            .char_indices()
            .map(|(i, _)| i)
            .chain(std::iter::once(input.len()))
            .collect();
        let mut scrubber = OverlapScrubber::new();
        let mut output = String::new();
        let mut i = 0;
        while i < boundaries.len() - 1 {
            let j = (i + 1 + next(&mut seed) as usize % 64).min(boundaries.len() - 1);
            output.push_str(&scrubber.push_chunk(&input[boundaries[i]..boundaries[j]]));
            i = j;
        }
        output.push_str(&scrubber.finish());
        assert!(!output.contains(secret), "case {n}");
        assert_eq!(output, expected, "case {n}");
    }
}
