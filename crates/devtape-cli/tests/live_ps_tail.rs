use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn live_ps_and_tail_stream_output_before_exit_and_strip_split_osc52() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("live_inspect.db");
    let tape = dir.path().join("live_inspect.tape");

    // Each write exceeds the 128-byte OverlapScrubber tail window with whitespace-delimited tokens
    // so two distinct StreamChunk events are committed to SQLite WAL while the child is still running,
    // with the OSC 52 sequence (\x1b]52;c;...c2VjcmV0\x07) genuinely split across the two StreamChunk events.
    let osc_part1 = "c2VjcmV0 ".repeat(25);
    let pad_b = "trailing ".repeat(25);
    let script = if cfg!(windows) {
        format!(
            "[Console]::Out.Write('phase1 ' + [char]27 + ']52;c;{osc_part1}'); [Console]::Out.Flush(); Start-Sleep -Milliseconds 600; [Console]::Out.Write('c2VjcmV0' + [char]7 + 'phase2' + [char]10 + '{pad_b}' + [char]10); [Console]::Out.Flush(); Start-Sleep -Seconds 3"
        )
    } else {
        format!(
            "printf 'phase1 \\033]52;c;{osc_part1}'; sleep 1; printf 'c2VjcmV0\\007phase2\\n{pad_b}\\n'; sleep 3"
        )
    };

    let mut cmd_args = vec![
        "record".to_string(),
        "--db".to_string(),
        db.to_str().unwrap().to_string(),
        "--out".to_string(),
        tape.to_str().unwrap().to_string(),
        "--".to_string(),
    ];
    if cfg!(windows) {
        std::fs::write(dir.path().join("child.ps1"), script).unwrap();
        cmd_args.extend(
            [
                "powershell",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                "child.ps1",
            ]
            .map(String::from),
        );
    } else {
        cmd_args.extend(["sh".into(), "-c".into(), script]);
    }

    let mut recorder = Command::new(env!("CARGO_BIN_EXE_devtape"))
        .current_dir(dir.path())
        .args(&cmd_args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // 1. Verify `devtape ps --json` sees the active recording while the child is still running.
    let ps_deadline = Instant::now() + Duration::from_secs(3);
    let active_session_id = loop {
        assert!(
            recorder.try_wait().unwrap().is_none(),
            "recorder exited before devtape ps observed it"
        );
        let ps_out = Command::new(env!("CARGO_BIN_EXE_devtape"))
            .current_dir(dir.path())
            .args(["ps", "--db", db.to_str().unwrap(), "--json"])
            .output()
            .unwrap();
        if ps_out.status.success() {
            let list: serde_json::Value = serde_json::from_slice(&ps_out.stdout).unwrap();
            if let Some(first) = list.as_array().and_then(|a| a.first()) {
                if first["status"] == "active" && first["event_count"].as_u64().unwrap_or(0) >= 2 {
                    break first["session_id"].as_str().unwrap().to_string();
                }
            }
        }
        assert!(
            Instant::now() < ps_deadline,
            "devtape ps did not observe active session before timeout"
        );
        std::thread::sleep(Duration::from_millis(50));
    };

    // 2. Spawn `devtape tail --latest --follow` and verify output is streamed BEFORE the child exits.
    let mut tail_child = Command::new(env!("CARGO_BIN_EXE_devtape"))
        .current_dir(dir.path())
        .args([
            "tail",
            "--latest",
            "--follow",
            "--filter",
            "pty",
            "--db",
            db.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let tail_stdout = tail_child.stdout.take().unwrap();
    let (line_tx, line_rx) = std::sync::mpsc::channel();
    let reader_thread = std::thread::spawn(move || {
        let mut reader = BufReader::new(tail_stdout);
        let mut collected = String::new();
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).unwrap();
            if n == 0 {
                break;
            }
            let _ = line_tx.send(line.clone());
            collected.push_str(&line);
        }
        collected
    });

    // Wait for `phase1 ... phase2` line to arrive from `devtape tail` while `recorder` is still in its final sleep!
    let first_line = line_rx
        .recv_timeout(Duration::from_secs(4))
        .expect("devtape tail should emit line before recorder exits");
    assert!(
        recorder.try_wait().unwrap().is_none(),
        "expected devtape tail to stream output before devtape record exits"
    );
    assert!(
        first_line.contains("phase1") && first_line.contains("phase2"),
        "expected sanitized combined line containing phase1 and phase2, got: {first_line:?}"
    );
    assert!(
        !first_line.contains("c2VjcmV0"),
        "split OSC 52 payload leaked into devtape tail output: {first_line:?}"
    );

    // Wait for both processes to finish cleanly.
    assert!(recorder.wait().unwrap().success());
    assert!(tail_child.wait().unwrap().success());
    let full_tail_output = reader_thread.join().unwrap();
    assert!(full_tail_output.contains("phase1") && full_tail_output.contains("phase2"));
    assert!(!full_tail_output.contains("c2VjcmV0"));

    // 3. After recording completes, `devtape ps` must report 0 active sessions.
    let ps_after = Command::new(env!("CARGO_BIN_EXE_devtape"))
        .current_dir(dir.path())
        .args(["ps", "--db", db.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(ps_after.status.success());
    let after_list: serde_json::Value = serde_json::from_slice(&ps_after.stdout).unwrap();
    assert_eq!(after_list.as_array().unwrap().len(), 0);

    // 4. Also verify `devtape tail <session-id> --json` works cleanly and sanitizes split OSC 52 in all stream_chunk events.
    let tail_json_out = Command::new(env!("CARGO_BIN_EXE_devtape"))
        .current_dir(dir.path())
        .args([
            "tail",
            &active_session_id,
            "--json",
            "--db",
            db.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(tail_json_out.status.success());
    let raw_json_lines = String::from_utf8_lossy(&tail_json_out.stdout);
    let mut combined_stream_data = String::new();
    for line in raw_json_lines.lines() {
        let env: serde_json::Value = serde_json::from_str(line).unwrap();
        if env["event"]["type"] == "stream_chunk" {
            let chunk_data = env["event"]["data"].as_str().unwrap();
            assert!(
                !chunk_data.contains("c2VjcmV0"),
                "split OSC 52 payload leaked in JSON stream_chunk: {chunk_data:?}"
            );
            combined_stream_data.push_str(chunk_data);
        }
    }
    assert!(combined_stream_data.contains("phase1") && combined_stream_data.contains("phase2"));
}

#[test]
fn ps_detects_stale_uncompleted_session() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("stale.db");
    let store = devtape_core::SessionStore::open(&db, Duration::from_millis(50)).unwrap();
    let manifest = dtp_codec::TapeManifest {
        spec_version: "0.1.0".into(),
        session_id: "sess_stale_orphan".into(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        shell: "sh".into(),
        qos_mode: dtp_codec::QosMode::ZeroStall,
        export_profile: dtp_codec::ExportProfile::Full,
        extensions: vec![],
        redaction: dtp_codec::RedactionAttestation {
            ruleset_version: "dtp-scrub-0.1".into(),
            redacted_count: 0,
            local_map_excluded: true,
        },
    };
    store.create_session(manifest).unwrap();
    store.close().unwrap();

    // After closing the store without emitting SessionEnd, wait 60ms and inspect with a 20ms stale threshold.
    std::thread::sleep(Duration::from_millis(60));
    let inspected = devtape_core::inspect_sessions(&db, 20).unwrap();
    assert_eq!(inspected.len(), 1);
    assert_eq!(inspected[0].session_id, "sess_stale_orphan");
    assert_eq!(inspected[0].status, devtape_core::SessionStatus::Stale);
}
