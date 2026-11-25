//! Micro-benchmark for `dtp-codec` encode, decode, and streaming ANSI replay sanitizer.
//! Run with `CARGO_INCREMENTAL=0 cargo bench --locked -p dtp-codec --bench codec_bench`.

use dtp_codec::{
    AnsiReplaySanitizer, CoreEvent, EventEnvelope, ExportProfile, HlcTimestamp, QosMode,
    RedactionAttestation, StreamChannel, TapeArchive, TapeManifest,
};
use std::{hint::black_box, time::Instant};

fn main() {
    let mut clock = HlcTimestamp::now(1);
    let mut events = Vec::with_capacity(200);
    for seq in 1..=200 {
        events.push(EventEnvelope {
            seq,
            hlc: clock.tick(1_760_000_000_000 + seq),
            span_id: "sp_bench0001".into(),
            parent_span_id: None,
            event: CoreEvent::StreamChunk {
                channel: StreamChannel::Stdout,
                data: "\x1b[32mcompiling\x1b[0m crate with normal output line\n".repeat(4),
            },
        });
    }
    let manifest = TapeManifest {
        spec_version: "0.1.0".into(),
        session_id: "sess_bench".into(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        shell: "zsh".into(),
        qos_mode: QosMode::ZeroStall,
        export_profile: ExportProfile::Full,
        extensions: vec![],
        redaction: RedactionAttestation {
            ruleset_version: "dtp-scrub-0.1".into(),
            redacted_count: 0,
            local_map_excluded: true,
        },
    };
    let archive = TapeArchive::new(manifest, events).expect("valid archive");

    let iterations = 100;
    let start_enc = Instant::now();
    let mut encoded = Vec::new();
    for _ in 0..iterations {
        encoded = black_box(archive.encode().expect("encode"));
    }
    let enc_elapsed = start_enc.elapsed();

    let start_dec = Instant::now();
    for _ in 0..iterations {
        let dec = black_box(TapeArchive::decode(&encoded).expect("decode"));
        assert_eq!(dec.events.len(), 200);
    }
    let dec_elapsed = start_dec.elapsed();

    let ansi_sample = "é\x1b[32mok\x1b[0m\x1b]52;c;clipboard\x07normal text\n".repeat(200);
    let start_ansi = Instant::now();
    for _ in 0..iterations {
        let mut s = AnsiReplaySanitizer::new();
        let mut out = s.push_chunk(&ansi_sample);
        out.push_str(&s.finish());
        black_box(out);
    }
    let ansi_elapsed = start_ansi.elapsed();

    println!(
        "encode_avg_ms={:.3} decode_avg_ms={:.3} ansi_sanitize_avg_ms={:.3} compressed_bytes={}",
        enc_elapsed.as_secs_f64() * 1000.0 / iterations as f64,
        dec_elapsed.as_secs_f64() * 1000.0 / iterations as f64,
        ansi_elapsed.as_secs_f64() * 1000.0 / iterations as f64,
        encoded.len()
    );
}
