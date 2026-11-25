use dtp_codec::{CoreEvent, ExportProfile, TapeArchive};
use std::{fs, process::Command};

fn run(dir: &std::path::Path, args: &[&str]) {
    let output = Command::new(env!("CARGO_BIN_EXE_devtape"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn embedded(html: &str) -> TapeArchive {
    let marker = "<script id=\"devtape-embedded-tape\" type=\"application/json\">";
    let data = html
        .split_once(marker)
        .unwrap()
        .1
        .split_once("</script>")
        .unwrap()
        .0;
    serde_json::from_str(data).unwrap()
}
#[test]
fn real_recording_exports_safe_standalone_html_and_profiles() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    if cfg!(windows) {
        fs::write(
            path.join("child.ps1"),
            "[Console]::Out.Write(\"ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8`n\"); [Console]::Out.Write([string][char]27 + ']5'); [Console]::Out.Flush(); Start-Sleep -Milliseconds 200; [Console]::Out.Write('2;c;c2VjcmV0' + [char]7 + '</script><img src=x onerror=alert(1)>'); [Console]::Out.Flush()",
        )
        .unwrap();
        run(
            path,
            &[
                "record",
                "--db",
                "sessions.db",
                "--out",
                "direct.tape",
                "--",
                "powershell",
                "-NoLogo",
                "-NoProfile",
                "-File",
                "child.ps1",
            ],
        );
    } else {
        fs::write(
            path.join("child.sh"),
            "printf 'ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\\n'; printf '\\033]5'; sleep 0.2; printf '2;c;c2VjcmV0\\007'; printf '</script><img src=x onerror=alert(1)>'",
        )
        .unwrap();
        run(
            path,
            &[
                "record",
                "--db",
                "sessions.db",
                "--out",
                "direct.tape",
                "--",
                "sh",
                "child.sh",
            ],
        );
    }
    let archive = TapeArchive::decode(&fs::read(path.join("direct.tape")).unwrap()).unwrap();
    let id = &archive.manifest.session_id;
    run(
        path,
        &[
            "export",
            id,
            "--db",
            "sessions.db",
            "--profile",
            "full",
            "--format",
            "html",
            "--review",
            "--out",
            "report.html",
        ],
    );
    let html = fs::read_to_string(path.join("report.html")).unwrap();
    assert!(!html.contains("ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"));
    assert!(html.contains("\\u003cDTP:REDACTED:GITHUB_TOKEN:"));
    assert!(!html.contains("c2VjcmV0"));
    assert!(!html.contains("</script><img"));
    let decoded = embedded(&html);
    assert!(decoded.events.iter().any(|e| matches!(&e.event, CoreEvent::StreamChunk { data, .. } if data.contains("</script><img src=x onerror=alert(1)>"))));
    run(
        path,
        &[
            "export",
            id,
            "--db",
            "sessions.db",
            "--profile",
            "trace-only",
            "--format",
            "html",
            "--out",
            "trace.html",
        ],
    );
    let trace = embedded(&fs::read_to_string(path.join("trace.html")).unwrap());
    assert!(!trace.events.iter().any(|e| matches!(
        e.event,
        CoreEvent::StreamChunk { .. } | CoreEvent::StateSnapshot { .. }
    )));
    run(
        path,
        &[
            "export",
            "direct.tape",
            "--profile",
            "diff-only",
            "--format",
            "html",
            "--out",
            "from_tape.html",
        ],
    );
    let diff = embedded(&fs::read_to_string(path.join("from_tape.html")).unwrap());
    assert_eq!(diff.manifest.export_profile, ExportProfile::DiffOnly);
}
