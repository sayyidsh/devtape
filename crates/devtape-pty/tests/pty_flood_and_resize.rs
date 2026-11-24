#![cfg(unix)]
use devtape_pty::{PtyRecorder, RecordConfig};
use dtp_codec::{CoreEvent, QosMode, StreamChannel};
use std::time::Duration;

fn config(script: &str) -> RecordConfig {
    RecordConfig {
        command: vec!["sh".into(), "-c".into(), script.into()],
        passthrough_stdout: false,
        ..RecordConfig::default()
    }
}

#[tokio::test]
async fn flood_stdout_with_yes_emits_drop_marker_without_freezing() {
    let mut c = config("yes devtape-flood-line-0123456789 | head -c 262144");
    c.max_buffer_bytes = 4096;
    c.qos_mode = QosMode::ZeroStall;
    let outcome = tokio::time::timeout(Duration::from_secs(10), PtyRecorder::record(c))
        .await
        .unwrap()
        .unwrap();
    assert!(outcome.bytes_dropped > 0);
    assert!(outcome
        .archive
        .events
        .iter()
        .any(|e| matches!(e.event, CoreEvent::DropMarker { .. })));
}

#[tokio::test]
async fn captures_nonzero_exit_code_from_real_shell() {
    let result = PtyRecorder::record(config("exit 42")).await.unwrap();
    assert_eq!(result.exit_code, 42);
    assert!(result
        .archive
        .events
        .iter()
        .any(|e| matches!(e.event, CoreEvent::SpanEnd { exit_code: 42, .. })));
}

#[tokio::test]
async fn live_terminal_resize_updates_child_pty_dimensions() {
    let (tx, rx) = tokio::sync::watch::channel((24, 80));
    let mut c = config("sleep 1; stty size");
    c.resize_rx = Some(rx);
    let task = tokio::spawn(PtyRecorder::record(c));
    tokio::time::sleep(Duration::from_millis(250)).await;
    tx.send((40, 120)).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let output: String = result
        .archive
        .events
        .iter()
        .filter_map(|e| match &e.event {
            CoreEvent::StreamChunk {
                channel: StreamChannel::Stdout,
                data,
            } => Some(data.as_str()),
            _ => None,
        })
        .collect();
    assert!(output.contains("40 120"), "{output:?}");
    assert!(result.archive.events.iter().any(|e| matches!(&e.event, CoreEvent::Extension {extension_id, event_name, payload} if extension_id == "ext.pty.v1" && event_name == "terminal_resize" && payload["rows"] == 40 && payload["cols"] == 120)));
}
