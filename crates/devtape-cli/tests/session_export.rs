#![cfg(unix)]
use dtp_codec::{CoreEvent, ExportProfile, TapeArchive};
use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
#[test]
fn record_list_and_export_session_via_cli() {
    let dir = std::env::temp_dir().join(format!(
        "devtape-store-cli-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sessions.db");
    let tape = dir.join("direct.tape");
    let out = Command::new(env!("CARGO_BIN_EXE_devtape"))
        .current_dir(&dir)
        .args([
            "record",
            "--db",
            db.to_str().unwrap(),
            "--out",
            tape.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            "printf hello",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let direct = TapeArchive::decode(&fs::read(tape).unwrap()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_devtape"))
        .current_dir(&dir)
        .args(["sessions", "--db", db.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let sessions: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(sessions[0]["session_id"], direct.manifest.session_id);
    let export = dir.join("trace.tape");
    let out = Command::new(env!("CARGO_BIN_EXE_devtape"))
        .current_dir(&dir)
        .args([
            "export",
            &direct.manifest.session_id,
            "--db",
            db.to_str().unwrap(),
            "--profile",
            "trace-only",
            "--review",
            "--out",
            export.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(report["session_id"], direct.manifest.session_id);
    let exported = TapeArchive::decode(&fs::read(export).unwrap()).unwrap();
    assert_eq!(exported.manifest.export_profile, ExportProfile::TraceOnly);
    assert!(!exported.events.iter().any(|e| matches!(
        e.event,
        CoreEvent::StreamChunk { .. } | CoreEvent::StateSnapshot { .. }
    )));
    fs::remove_dir_all(dir).unwrap();
}
