#![cfg(unix)]
use devtape_pty::{PtyRecorder, RecordConfig};
use dtp_codec::{CoreEvent, StreamChannel};

#[tokio::test]
async fn split_pty_output_is_redacted_and_attested() {
    let outcome = PtyRecorder::record(RecordConfig {
        command: vec![
            "sh".into(),
            "-c".into(),
            "printf sk-proj-1234567890; sleep 0.2; printf abcdefghijklmno".into(),
        ],
        passthrough_stdout: false,
        ..RecordConfig::default()
    })
    .await
    .unwrap();
    let output: String = outcome
        .archive
        .events
        .iter()
        .filter_map(|event| match &event.event {
            CoreEvent::StreamChunk {
                channel: StreamChannel::Stdout,
                data,
            } => Some(data.as_str()),
            _ => None,
        })
        .collect();
    assert!(!output.contains("sk-proj-1234567890abcdefghijklmno"));
    assert!(output.contains("<DTP:REDACTED:API_KEY:"));
    assert!(outcome.archive.manifest.redaction.redacted_count >= 1);
    assert!(outcome.archive.manifest.redaction.local_map_excluded);
}
