use clap::{Parser, Subcommand};
use devtape_scrub::{OverlapScrubber, RULESET_VERSION};
use dtp_codec::{
    CoreEvent, EventEnvelope, ExportProfile, HlcTimestamp, QosMode, RedactionAttestation,
    StreamChannel, TapeArchive, TapeManifest,
};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "devtape",
    version,
    about = "Reference CLI for the DevTape Protocol (DTP v0.1)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a valid sample DTP v0.1 .tape archive to test the codec pipeline.
    DemoTape {
        #[arg(long, default_value = "sample.tape")]
        out: PathBuf,
    },
    /// Inspect a .tape file's manifest, redaction attestation, and event timeline.
    Inspect {
        path: PathBuf,
    },
    /// Read stdin through the sliding-window secret scrubber and print the sanitized output.
    ScrubCheck,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::DemoTape { out } => {
            let mut scrubber = OverlapScrubber::new();
            let raw_output = "Running tests with token=sk-proj-secretvalue12345678901234\n";
            let mut scrubbed = scrubber.push_chunk(raw_output);
            scrubbed.push_str(&scrubber.finish());

            let mut clock = HlcTimestamp::now(1);
            let t1 = clock.tick(clock.physical_ms);
            let t2 = clock.tick(clock.physical_ms);
            let t3 = clock.tick(clock.physical_ms);

            let manifest = TapeManifest {
                spec_version: "0.1.0".into(),
                session_id: "demo-session-001".into(),
                os: std::env::consts::OS.into(),
                arch: std::env::consts::ARCH.into(),
                shell: std::env::var("SHELL").unwrap_or_else(|_| "unknown".into()),
                qos_mode: QosMode::ZeroStall,
                export_profile: ExportProfile::Full,
                extensions: vec!["ext.git.v1".into(), "ext.mcp.v1".into()],
                redaction: RedactionAttestation {
                    ruleset_version: RULESET_VERSION.into(),
                    redacted_count: scrubber.redacted_count(),
                    local_map_excluded: true,
                },
            };

            let events = vec![
                EventEnvelope {
                    seq: 1,
                    hlc: t1,
                    span_id: "sp_0001".into(),
                    parent_span_id: None,
                    event: CoreEvent::SpanStart {
                        kind: "command".into(),
                        label: "cargo test".into(),
                    },
                },
                EventEnvelope {
                    seq: 2,
                    hlc: t2,
                    span_id: "sp_0001".into(),
                    parent_span_id: None,
                    event: CoreEvent::StreamChunk {
                        channel: StreamChannel::Stdout,
                        data: scrubbed,
                    },
                },
                EventEnvelope {
                    seq: 3,
                    hlc: t3,
                    span_id: "sp_0001".into(),
                    parent_span_id: None,
                    event: CoreEvent::SpanEnd {
                        exit_code: 0,
                        duration_ms: 42,
                    },
                },
            ];

            let archive = TapeArchive::new(manifest, events)?;
            let encoded = archive.encode()?;
            fs::write(&out, &encoded)?;
            println!(
                "Wrote DTP v0.1 archive to {} ({} bytes compressed, {} secrets scrubbed)",
                out.display(),
                encoded.len(),
                archive.manifest.redaction.redacted_count
            );
        }
        Commands::Inspect { path } => {
            let bytes = fs::read(&path)?;
            let archive = TapeArchive::decode(&bytes)?;
            println!("{}", serde_json::to_string_pretty(&archive)?);
        }
        Commands::ScrubCheck => {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input)?;
            let mut scrubber = OverlapScrubber::new();
            let mut out = scrubber.push_chunk(&input);
            out.push_str(&scrubber.finish());
            print!("{out}");
            eprintln!(
                "\n[devtape-scrub] ruleset={} redacted_count={}",
                RULESET_VERSION,
                scrubber.redacted_count()
            );
        }
    }
    Ok(())
}
