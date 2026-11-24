use devtape_core::SessionStore;
use dtp_codec::{
    CoreEvent, EventEnvelope, ExportProfile, HlcTimestamp, QosMode, RedactionAttestation,
    StreamChannel, TapeArchive, TapeManifest,
};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn store() -> (Temp, SessionStore) {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let p = std::env::temp_dir().join(format!(
        "devtape-core-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&p).unwrap();
    let s = SessionStore::open(p.join("session.db"), Duration::from_millis(300)).unwrap();
    (Temp(p), s)
}
fn manifest(id: &str) -> TapeManifest {
    TapeManifest {
        spec_version: "0.1.0".into(),
        session_id: id.into(),
        os: "test".into(),
        arch: "test".into(),
        shell: "sh".into(),
        qos_mode: QosMode::ZeroStall,
        export_profile: ExportProfile::Full,
        extensions: vec!["ext.git.v1".into()],
        redaction: RedactionAttestation {
            ruleset_version: "test".into(),
            redacted_count: 0,
            local_map_excluded: true,
        },
    }
}
fn event(seq: u64, e: CoreEvent) -> EventEnvelope {
    EventEnvelope {
        seq,
        hlc: HlcTimestamp {
            physical_ms: seq,
            logical: 0,
            node_id: 1,
        },
        span_id: "span".into(),
        parent_span_id: None,
        event: e,
    }
}
#[test]
fn four_producer_threads_concurrent_wal_stress_test() {
    let (tmp, s) = store();
    s.create_session(manifest("stress")).unwrap();
    let mut threads = Vec::new();
    for producer in 0..4 {
        let handle = s.clone();
        threads.push(std::thread::spawn(move || {
            for i in 0..750 {
                let n = (producer * 750 + i + 1) as u64;
                handle
                    .send_event(
                        "stress",
                        event(
                            n,
                            CoreEvent::DropMarker {
                                bytes_dropped: 1,
                                reason: "stress".into(),
                            },
                        ),
                    )
                    .unwrap();
            }
        }));
    }
    for t in threads {
        t.join().unwrap();
    }
    s.flush().unwrap();
    let list = s.sessions().unwrap();
    assert_eq!(list[0].event_count, 3000);
    let (a, _) = s.export_session("stress", ExportProfile::Full).unwrap();
    assert_eq!(a.events.len(), 3000);
    assert!(a.events.windows(2).all(|w| w[0].hlc < w[1].hlc));
    s.close().unwrap();
    let db = rusqlite::Connection::open(tmp.0.join("session.db")).unwrap();
    let mode: String = db
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    let count: u64 = db
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 3000);
}
#[test]
fn export_profiles_enforce_privacy_and_roundtrip_decode() {
    let (_tmp, s) = store();
    s.create_session(manifest("privacy")).unwrap();
    let key = "sk-proj-1234567890abcdefghijklmno";
    let items = vec![
        CoreEvent::SessionStart {
            sanitized_cwd: format!("/tmp/{key}"),
            env_fingerprint: "env".into(),
        },
        CoreEvent::SpanStart {
            kind: "command".into(),
            label: format!("token {key}"),
        },
        CoreEvent::StreamChunk {
            channel: StreamChannel::Stdin,
            data: "sk-proj-1234567890".into(),
        },
        CoreEvent::StreamChunk {
            channel: StreamChannel::Stdin,
            data: "abcdefghijklmno".into(),
        },
        CoreEvent::StreamChunk {
            channel: StreamChannel::Stdout,
            data: key.into(),
        },
        CoreEvent::StreamChunk {
            channel: StreamChannel::Stderr,
            data: key.into(),
        },
        CoreEvent::DropMarker {
            bytes_dropped: 1,
            reason: "drop".into(),
        },
        CoreEvent::StateSnapshot {
            tree_blake3: "hash".into(),
            changed_files: vec![format!("src/{key}.txt")],
        },
        CoreEvent::Extension {
            extension_id: "ext.git.v1".into(),
            event_name: "shadow_snapshot".into(),
            payload: serde_json::json!({"path":key}),
        },
        CoreEvent::SpanEnd {
            exit_code: 4,
            duration_ms: 1,
        },
        CoreEvent::SessionEnd {
            total_events: 11,
            duration_ms: 1,
        },
    ];
    for (i, e) in items.into_iter().enumerate() {
        s.send_event("privacy", event(i as u64 + 1, e)).unwrap();
    }
    for profile in [
        ExportProfile::Full,
        ExportProfile::DiffOnly,
        ExportProfile::TraceOnly,
    ] {
        let (a, r) = s.export_session("privacy", profile).unwrap();
        let encoded = a.encode().unwrap();
        let decoded = TapeArchive::decode(&encoded).unwrap();
        assert!(!serde_json::to_string(&decoded).unwrap().contains(key));
        assert!(decoded.manifest.redaction.local_map_excluded);
        assert_eq!(r.total_events_stored, 11);
        assert_eq!(r.exported_events_count, decoded.events.len());
        assert!(r.redacted_count > 0);
        assert_eq!(
            r.excluded_stream_chunks,
            if profile == ExportProfile::Full { 0 } else { 4 }
        );
        assert_eq!(
            r.excluded_snapshots,
            if profile == ExportProfile::TraceOnly {
                1
            } else {
                0
            }
        );
        assert!(decoded
            .events
            .iter()
            .enumerate()
            .all(|(i, e)| e.seq == i as u64 + 1));
        if profile != ExportProfile::Full {
            assert!(!decoded
                .events
                .iter()
                .any(|e| matches!(e.event, CoreEvent::StreamChunk { .. })));
        }
        if profile == ExportProfile::DiffOnly {
            assert!(decoded
                .events
                .iter()
                .any(|e| matches!(e.event, CoreEvent::StateSnapshot { .. })));
            assert!(decoded.events.iter().any(|e|matches!(&e.event,CoreEvent::Extension{extension_id,..} if extension_id=="ext.git.v1")));
        }
        if profile == ExportProfile::TraceOnly {
            assert!(!decoded.events.iter().any(|e| matches!(
                e.event,
                CoreEvent::StateSnapshot { .. } | CoreEvent::Extension { .. }
            )));
            assert!(decoded
                .events
                .iter()
                .any(|e| matches!(e.event, CoreEvent::DropMarker { .. })));
            assert!(!decoded
                .manifest
                .extensions
                .iter()
                .any(|x| x == "ext.git.v1"));
        }
    }
    s.close().unwrap();
}
