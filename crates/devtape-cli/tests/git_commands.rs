use std::{
    fs,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
fn git(dir: &Path, args: &[&str]) -> Vec<u8> {
    let o = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    o.stdout
}
fn cli(dir: &Path, args: &[&str]) -> serde_json::Value {
    let o = Command::new(env!("CARGO_BIN_EXE_devtape"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    serde_json::from_slice(&o.stdout).unwrap()
}
#[test]
fn cli_snapshot_rewind_and_undo() {
    let dir = std::env::temp_dir().join(format!(
        "devtape-cli-git-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(dir.join("src")).unwrap();
    git(&dir, &["init", "-q"]);
    git(&dir, &["config", "user.name", "Test"]);
    git(&dir, &["config", "user.email", "test@example.test"]);
    for f in ["a.txt", "b.txt", "src/c.rs"] {
        fs::write(dir.join(f), format!("original {f}")).unwrap();
    }
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-qm", "initial"]);
    let snap = cli(&dir, &["snapshot"]);
    let id = snap["snapshot_id"].as_str().unwrap();
    let index = fs::read(dir.join(".git/index")).unwrap();
    let head = git(&dir, &["log", "--format=%H"]);
    for f in ["a.txt", "b.txt", "src/c.rs"] {
        fs::write(dir.join(f), format!("changed {f}")).unwrap();
    }
    fs::write(dir.join("untracked_notes.txt"), "notes").unwrap();
    let outcome = cli(&dir, &["rewind", "--to", id]);
    assert_eq!(outcome["pre_rewind"]["label"], "pre-rewind");
    for f in ["a.txt", "b.txt", "src/c.rs"] {
        assert_eq!(
            fs::read(dir.join(f)).unwrap(),
            format!("original {f}").as_bytes()
        );
    }
    assert!(!dir.join("untracked_notes.txt").exists());
    cli(&dir, &["undo-rewind"]);
    for f in ["a.txt", "b.txt", "src/c.rs"] {
        assert_eq!(
            fs::read(dir.join(f)).unwrap(),
            format!("changed {f}").as_bytes()
        );
    }
    assert_eq!(fs::read(dir.join("untracked_notes.txt")).unwrap(), b"notes");
    assert_eq!(index, fs::read(dir.join(".git/index")).unwrap());
    assert_eq!(head, git(&dir, &["log", "--format=%H"]));
    let tape = dir.join("recorded.tape");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_devtape"));
    cmd.current_dir(&dir)
        .args(["record", "--out", tape.to_str().unwrap(), "--"]);
    if cfg!(windows) {
        cmd.args(["cmd.exe", "/C", "echo recorded"]);
    } else {
        cmd.args(["sh", "-c", "printf recorded"]);
    }
    let run = cmd.output().unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let archive = dtp_codec::TapeArchive::decode(&fs::read(tape).unwrap()).unwrap();
    assert!(archive
        .manifest
        .extensions
        .iter()
        .any(|x| x == "ext.git.v1"));
    assert!(archive
        .events
        .iter()
        .any(|e| matches!(e.event, dtp_codec::CoreEvent::StateSnapshot { .. })));
    assert!(archive.events.iter().any(|e| matches!(&e.event, dtp_codec::CoreEvent::Extension { extension_id, .. } if extension_id == "ext.git.v1")));
    assert!(
        matches!(&archive.events.last().unwrap().event, dtp_codec::CoreEvent::SessionEnd { total_events, .. } if *total_events == archive.events.len() as u64)
    );
    fs::remove_dir_all(dir).unwrap();
}
