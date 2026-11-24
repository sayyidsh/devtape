use dtp_codec::*;
use std::{fs, io::Cursor, path::PathBuf};

fn manifest() -> TapeManifest {
    TapeManifest {
        spec_version: "0.1.0".into(),
        session_id: "vector".into(),
        os: "test".into(),
        arch: "test".into(),
        shell: "sh".into(),
        qos_mode: QosMode::ZeroStall,
        export_profile: ExportProfile::Full,
        extensions: vec![],
        redaction: RedactionAttestation {
            ruleset_version: "dtp-scrub-0.1".into(),
            redacted_count: 0,
            local_map_excluded: true,
        },
    }
}
fn envelope(seq: u64, event: CoreEvent) -> EventEnvelope {
    EventEnvelope {
        seq,
        hlc: HlcTimestamp {
            physical_ms: 1000,
            logical: seq as u32,
            node_id: 1,
        },
        span_id: "root".into(),
        parent_span_id: None,
        event,
    }
}
fn container(archive: &TapeArchive) -> Vec<u8> {
    let json = serde_json::to_vec(archive).unwrap();
    let mut out = b"DTAP01\0\x01".to_vec();
    out.extend_from_slice(&(json.len() as u64).to_be_bytes());
    out.extend(zstd::stream::encode_all(Cursor::new(json), 3).unwrap());
    out
}
fn start() -> CoreEvent {
    CoreEvent::SessionStart {
        sanitized_cwd: "~".into(),
        env_fingerprint: "test".into(),
    }
}
fn end() -> CoreEvent {
    CoreEvent::SessionEnd {
        total_events: 2,
        duration_ms: 1,
    }
}
#[test]
fn generate_and_validate_conformance_vectors() {
    let mut vectors: Vec<(String, String, String, Vec<u8>)> = Vec::new();
    let names = [
        "minimal_session",
        "command_span_stdout",
        "multichannel_stdio",
        "split_chunk_redacted_secrets",
        "qos0_drop_marker",
        "state_snapshot_safe_paths",
        "hlc_causal_dag_nested_spans",
        "unknown_future_extension_v99",
        "export_profile_diff_only",
        "export_profile_trace_only",
    ];
    for (i, name) in names.iter().enumerate() {
        let mut m = manifest();
        let mut events = vec![envelope(1, start())];
        let mut add = |e| events.push(envelope(events.len() as u64 + 1, e));
        match i {
            1 => {
                add(CoreEvent::SpanStart {
                    kind: "command".into(),
                    label: "echo hi".into(),
                });
                add(CoreEvent::StreamChunk {
                    channel: StreamChannel::Stdout,
                    data: "hi".into(),
                });
                add(CoreEvent::SpanEnd {
                    exit_code: 0,
                    duration_ms: 1,
                });
            }
            2 => {
                for channel in [
                    StreamChannel::Stdin,
                    StreamChannel::Stdout,
                    StreamChannel::Stderr,
                ] {
                    add(CoreEvent::StreamChunk {
                        channel,
                        data: "data".into(),
                    });
                }
            }
            3 => {
                m.redaction.redacted_count = 2;
                add(CoreEvent::StreamChunk {
                    channel: StreamChannel::Stdout,
                    data: "<DTP:REDACTED:API_KEY:123456> <DTP:REDACTED:AWS_KEY:abcdef>".into(),
                });
            }
            4 => add(CoreEvent::DropMarker {
                bytes_dropped: 123,
                reason: "backpressure".into(),
            }),
            5 => add(CoreEvent::StateSnapshot {
                tree_blake3: "abc".into(),
                changed_files: vec!["src/lib.rs".into(), "Cargo.toml".into()],
            }),
            6 => {
                add(CoreEvent::SpanStart {
                    kind: "child".into(),
                    label: "nested".into(),
                });
                events[1].span_id = "child".into();
                events[1].parent_span_id = Some("root".into());
                events[1].hlc.node_id = 2;
            }
            7 => add(CoreEvent::Extension {
                extension_id: "ext.future.v99".into(),
                event_name: "future".into(),
                payload: serde_json::json!({"hello": [1,2,3]}),
            }),
            8 => m.export_profile = ExportProfile::DiffOnly,
            9 => m.export_profile = ExportProfile::TraceOnly,
            _ => {}
        }
        events.push(envelope(events.len() as u64 + 1, end()));
        let archive = TapeArchive::new(m, events).unwrap();
        vectors.push((
            format!("{:02}_{}.tape", i + 1, name),
            "valid".into(),
            name.to_string(),
            archive.encode().unwrap(),
        ));
    }
    let base = vectors[0].3.clone();
    let mut invalid = base.clone();
    invalid[0] = b'X';
    vectors.push((
        "11_invalid_magic_header.tape".into(),
        "InvalidMagic".into(),
        "invalid magic".into(),
        invalid,
    ));
    let mut invalid = base.clone();
    invalid[6..8].copy_from_slice(&99u16.to_be_bytes());
    vectors.push((
        "12_unsupported_version_99.tape".into(),
        "UnsupportedVersion(99)".into(),
        "unsupported version".into(),
        invalid,
    ));
    let mut invalid = base.clone();
    invalid[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    vectors.push((
        "13_decompression_bomb_declared_header.tape".into(),
        "DecompressionLimitExceeded".into(),
        "declared size exceeds limit".into(),
        invalid,
    ));
    let zeros = vec![0u8; 1024 * 1024];
    let mut bomb = b"DTAP01\0\x01".to_vec();
    bomb.extend_from_slice(&4096u64.to_be_bytes());
    bomb.extend(zstd::stream::encode_all(Cursor::new(zeros), 3).unwrap());
    vectors.push((
        "14_decompression_bomb_zstd_stream.tape".into(),
        "DecompressionLimitExceeded".into(),
        "compressed zeros exceed ratio".into(),
        bomb,
    ));
    let mut archive = TapeArchive::decode(&base).unwrap();
    archive.events.push(envelope(
        3,
        CoreEvent::StateSnapshot {
            tree_blake3: "x".into(),
            changed_files: vec!["../../etc/passwd".into()],
        },
    ));
    vectors.push((
        "15_path_traversal_dotdot.tape".into(),
        "UnsafePath".into(),
        "path traversal".into(),
        container(&archive),
    ));
    let mut archive = TapeArchive::decode(&base).unwrap();
    archive.integrity_blake3 = "bad".into();
    vectors.push((
        "16_tampered_integrity_blake3.tape".into(),
        "IntegrityMismatch".into(),
        "integrity tampering".into(),
        container(&archive),
    ));
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/conformance");
    fs::create_dir_all(&dir).unwrap();
    let mut index = Vec::new();
    for (name, expected, description, bytes) in vectors {
        let result = TapeArchive::decode(&bytes);
        let ok = matches!(
            (&*expected, result),
            ("valid", Ok(_))
                | ("InvalidMagic", Err(CodecError::InvalidMagic))
                | (
                    "UnsupportedVersion(99)",
                    Err(CodecError::UnsupportedVersion(99))
                )
                | (
                    "DecompressionLimitExceeded",
                    Err(CodecError::DecompressionLimitExceeded { .. })
                )
                | ("UnsafePath", Err(CodecError::UnsafePath(_)))
                | ("IntegrityMismatch", Err(CodecError::IntegrityMismatch))
        );
        assert!(ok, "{name} expected {expected}");
        let path = dir.join(&name);
        if path.exists() {
            assert_eq!(
                fs::read(&path).unwrap(),
                bytes,
                "golden vector changed: {name}"
            );
        } else {
            fs::write(path, bytes).unwrap();
        }
        index.push(
            serde_json::json!({"filename":name,"expected":expected,"description":description}),
        );
    }
    let manifest_path = dir.join("manifest.json");
    let expected = serde_json::to_vec_pretty(&index).unwrap();
    if manifest_path.exists() {
        assert_eq!(fs::read(manifest_path).unwrap(), expected);
    } else {
        fs::write(manifest_path, expected).unwrap();
    }
}
