#![forbid(unsafe_code)]

//! Generate a signed-by-hash fixture for the browser binding's runtime tests.
use dtp_codec::{CoreEvent, StreamChannel, TapeArchive};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut archive = TapeArchive::decode(include_bytes!(
        "../../../spec/conformance/01_minimal_session.tape"
    ))?;
    let template = archive.events[0].clone();
    archive.events = [
        CoreEvent::SpanStart {
            kind: "command".into(),
            label: "test\x1b]52;c;CLIPBOARD_SECRET\x07".into(),
        },
        CoreEvent::StreamChunk {
            channel: StreamChannel::Stdout,
            data: "hello\x1b]5".into(),
        },
        CoreEvent::StreamChunk {
            channel: StreamChannel::Stderr,
            data: "error\x1b]52;c;OTHER_SECRET\x07safe".into(),
        },
        CoreEvent::StreamChunk {
            channel: StreamChannel::Stdout,
            data: "2;c;CLIPBOARD_SECRET\x07world".into(),
        },
        CoreEvent::StateSnapshot {
            tree_blake3: "abc123".into(),
            changed_files: vec!["src/lib.rs".into()],
        },
    ]
    .into_iter()
    .enumerate()
    .map(|(index, event)| {
        let mut envelope = template.clone();
        envelope.seq = index as u64 + 1;
        envelope.event = event;
        envelope
    })
    .collect();
    let archive = TapeArchive::new(archive.manifest, archive.events)?;
    let path = std::env::args_os().nth(1).ok_or("expected output path")?;
    std::fs::write(path, archive.encode()?)?;
    Ok(())
}
