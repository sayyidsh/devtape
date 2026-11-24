#![forbid(unsafe_code)]

use dtp_codec::{CoreEvent, ExportProfile, TapeArchive};
use serde_json::json;
use std::{fs, process::Command};

#[test]
fn records_scrubbed_ci_context_and_preserves_it_in_diff_export() {
    for exit_code in [0, 101] {
        let temp = tempfile::tempdir().unwrap();
        let tape = temp.path().join("ci.tape");
        let db = temp.path().join("sessions.db");
        let mut command = Command::new(env!("CARGO_BIN_EXE_devtape"));
        command
            .current_dir(temp.path())
            .env("GITHUB_ACTIONS", "true")
            .env("GITHUB_REPOSITORY", "sayyidsh/devtape")
            .env("GITHUB_RUN_ID", "98765")
            .env("GITHUB_SHA", "deadbeef")
            .env(
                "GITHUB_REF_NAME",
                "secret-branch-sk-proj-1234567890abcdefghijklmno",
            )
            .env("RUNNER_OS", "macOS")
            .args(["record", "--qos", "lossless", "--db"])
            .arg(&db)
            .arg("--out")
            .arg(&tape)
            .arg("--");
        if cfg!(windows) {
            command.args(["cmd.exe", "/C", &format!("exit /b {exit_code}")]);
        } else {
            command.args(["sh", "-c", &format!("exit {exit_code}")]);
        }
        let result = command.output().unwrap();
        assert_eq!(
            result.status.code(),
            Some(exit_code),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let archive = TapeArchive::decode(&fs::read(&tape).unwrap()).unwrap();
        assert_eq!(
            archive
                .manifest
                .extensions
                .iter()
                .filter(|id| *id == "ext.ci.v1")
                .count(),
            1
        );
        let event = &archive.events[archive.events.len() - 2];
        let CoreEvent::Extension {
            extension_id,
            event_name,
            payload,
        } = &event.event
        else {
            panic!("CI context must precede SessionEnd");
        };
        assert_eq!(extension_id, "ext.ci.v1");
        assert_eq!(event_name, "ci_context");
        let mut scrubber = devtape_scrub::Scrubber::new();
        assert_eq!(
            payload,
            &json!({
                "provider": "github_actions", "github_actions": "true", "repository": "sayyidsh/devtape",
                "run_id": "98765", "sha": "deadbeef", "ref_name": scrubber.scrub_str("secret-branch-sk-proj-1234567890abcdefghijklmno"),
                "runner_os": "macOS", "exit_code": exit_code
            })
        );
        assert!(payload["ref_name"]
            .as_str()
            .unwrap()
            .contains("<DTP:REDACTED:API_KEY:"));
        assert!(archive.manifest.redaction.redacted_count >= 1);
        assert!(!serde_json::to_string(&archive)
            .unwrap()
            .contains("sk-proj-1234567890abcdefghijklmno"));
        for (index, event) in archive.events.iter().enumerate() {
            assert_eq!(event.seq, index as u64 + 1);
        }
        assert!(archive
            .events
            .windows(2)
            .all(|pair| pair[0].hlc < pair[1].hlc));
        assert!(
            matches!(archive.events.last().unwrap().event, CoreEvent::SessionEnd { total_events, .. } if total_events == archive.events.len() as u64)
        );
        let exported = temp.path().join("diff.tape");
        let output = Command::new(env!("CARGO_BIN_EXE_devtape"))
            .args(["export", &archive.manifest.session_id, "--db"])
            .arg(&db)
            .args(["--profile", "diff-only", "--review", "--out"])
            .arg(&exported)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let diff = TapeArchive::decode(&fs::read(exported).unwrap()).unwrap();
        assert_eq!(diff.manifest.export_profile, ExportProfile::DiffOnly);
        assert!(diff.manifest.extensions.iter().any(|id| id == "ext.ci.v1"));
        assert!(diff.events.iter().any(|e| matches!(&e.event, CoreEvent::Extension { extension_id, payload: p, .. } if extension_id == "ext.ci.v1" && p == payload)));
        assert!(!diff
            .events
            .iter()
            .any(|e| matches!(e.event, CoreEvent::StreamChunk { .. })));
    }
}
