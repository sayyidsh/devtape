//! Run with `CARGO_INCREMENTAL=0 cargo bench --locked -p devtape-scrub --bench scrub_bench`.
use devtape_scrub::OverlapScrubber;
use std::{hint::black_box, time::Instant};
fn main() {
    let input = "normal terminal line with unicode 文 and ordinary text\n".repeat(1000);
    let loops = 100;
    let start = Instant::now();
    for _ in 0..loops {
        let mut scrubber = OverlapScrubber::new();
        for chunk in input.as_bytes().chunks(1024) {
            // Bytes may end inside UTF-8, so process via a lossy conversion in this harness.
            black_box(scrubber.push_chunk(&String::from_utf8_lossy(chunk)));
        }
        black_box(scrubber.finish());
    }
    let elapsed = start.elapsed();
    println!(
        "bytes={} elapsed_ms={} throughput_mib_s={:.2}",
        input.len() * loops,
        elapsed.as_millis(),
        (input.len() * loops) as f64 / 1_048_576.0 / elapsed.as_secs_f64()
    );
}
