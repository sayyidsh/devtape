use devtape_git::GitSnapshotEngine;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn run(dir: &Path, args: &[&str]) -> Vec<u8> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}
fn repo() -> Temp {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let p = std::env::temp_dir().join(format!(
        "devtape-git-test-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(p.join("src")).unwrap();
    let r = Temp(p);
    run(&r.0, &["init", "-q"]);
    run(&r.0, &["config", "user.name", "DevTape Test"]);
    run(&r.0, &["config", "user.email", "devtape@example.test"]);
    for f in ["a.txt", "b.txt", "src/c.rs"] {
        fs::write(r.0.join(f), format!("original {f}\n")).unwrap();
    }
    fs::write(r.0.join(".gitignore"), "ignored.txt\n").unwrap();
    run(&r.0, &["add", "."]);
    run(&r.0, &["commit", "-qm", "initial"]);
    r
}
#[test]
fn shadow_snapshot_leaves_git_status_index_and_log_untouched() {
    let r = repo();
    fs::write(r.0.join("a.txt"), "staged").unwrap();
    run(&r.0, &["add", "a.txt"]);
    fs::write(r.0.join("b.txt"), "unstaged").unwrap();
    fs::write(r.0.join("new.txt"), "new").unwrap();
    fs::write(r.0.join("ignored.txt"), "ignored").unwrap();
    let status = run(&r.0, &["status", "--porcelain=v1"]);
    let index = fs::read(r.0.join(".git/index")).unwrap();
    let log = run(&r.0, &["log", "--format=%H"]);
    let s = GitSnapshotEngine::create_snapshot(&r.0, Some("test")).unwrap();
    assert_eq!(status, run(&r.0, &["status", "--porcelain=v1"]));
    assert_eq!(index, fs::read(r.0.join(".git/index")).unwrap());
    assert_eq!(log, run(&r.0, &["log", "--format=%H"]));
    let tree = run(&r.0, &["ls-tree", "-r", "--name-only", &s.git_tree_oid]);
    let tree = String::from_utf8(tree).unwrap();
    assert!(tree.contains("new.txt"));
    assert!(!tree.contains("ignored.txt"));
}
#[test]
fn rewind_and_undo_rewind_across_three_modified_and_one_untracked_file() {
    let r = repo();
    let s = GitSnapshotEngine::create_snapshot(&r.0, None).unwrap();
    let mut expected = Vec::new();
    for f in ["a.txt", "b.txt", "src/c.rs"] {
        expected.push(fs::read(r.0.join(f)).unwrap());
        fs::write(r.0.join(f), format!("changed {f}")).unwrap();
    }
    fs::write(r.0.join("untracked_notes.txt"), "notes").unwrap();
    let index = fs::read(r.0.join(".git/index")).unwrap();
    let head = run(&r.0, &["log", "--format=%H"]);
    let o = GitSnapshotEngine::rewind(&r.0, Some(&s.snapshot_id)).unwrap();
    assert_eq!(o.pre_rewind.label.as_deref(), Some("pre-rewind"));
    for (i, f) in ["a.txt", "b.txt", "src/c.rs"].iter().enumerate() {
        assert_eq!(fs::read(r.0.join(f)).unwrap(), expected[i]);
    }
    assert!(!r.0.join("untracked_notes.txt").exists());
    assert_eq!(index, fs::read(r.0.join(".git/index")).unwrap());
    assert_eq!(head, run(&r.0, &["log", "--format=%H"]));
    GitSnapshotEngine::undo_rewind(&r.0).unwrap();
    for f in ["a.txt", "b.txt", "src/c.rs"] {
        assert_eq!(
            fs::read(r.0.join(f)).unwrap(),
            format!("changed {f}").as_bytes()
        );
    }
    assert_eq!(fs::read(r.0.join("untracked_notes.txt")).unwrap(), b"notes");
    assert_eq!(index, fs::read(r.0.join(".git/index")).unwrap());
    assert_eq!(head, run(&r.0, &["log", "--format=%H"]));
}
#[test]
fn fastcdc_deduplicates_large_binary_file_modifications() {
    let r = repo();
    let mut seed = 123456789u64;
    let mut data = vec![0; 400_000];
    for x in &mut data {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *x = seed as u8;
    }
    fs::write(r.0.join("large.bin"), &data).unwrap();
    GitSnapshotEngine::create_snapshot(&r.0, None).unwrap();
    let cas = r.0.join(".git/devtape/cas");
    let before: std::collections::HashSet<_> = fs::read_dir(&cas)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(before.len() > 1);
    data[399_900] ^= 1;
    fs::write(r.0.join("large.bin"), data).unwrap();
    GitSnapshotEngine::create_snapshot(&r.0, None).unwrap();
    let after: std::collections::HashSet<_> = fs::read_dir(cas)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(before.is_subset(&after));
    assert!(after.len() > before.len());
    assert!(after.len() - before.len() < before.len());
}
#[test]
fn rewind_refuses_to_overwrite_ignored_collision() {
    let r = repo();
    fs::write(r.0.join("later.txt"), "snapshot").unwrap();
    let s = GitSnapshotEngine::create_snapshot(&r.0, None).unwrap();
    fs::remove_file(r.0.join("later.txt")).unwrap();
    fs::write(r.0.join(".gitignore"), "ignored.txt\nlater.txt\n").unwrap();
    fs::write(r.0.join("later.txt"), "ignored data").unwrap();
    assert!(GitSnapshotEngine::rewind(&r.0, Some(&s.snapshot_id)).is_err());
    assert_eq!(fs::read(r.0.join("later.txt")).unwrap(), b"ignored data");
}

#[test]
fn undo_restores_raw_bytes_and_permissions_with_lossy_attributes() {
    let r = repo();
    fs::write(r.0.join(".gitattributes"), "*.dat text eol=lf ident\n").unwrap();
    fs::write(r.0.join("preserved.dat"), b"snapshot bytes\n$Id$\n").unwrap();
    run(&r.0, &["add", ".gitattributes", "preserved.dat"]);
    run(&r.0, &["commit", "-qm", "add attributed fixture"]);
    let target = GitSnapshotEngine::create_snapshot(&r.0, None).unwrap();

    let exact = b"local bytes\r\n$Id: keep this spelling $\r\n";
    fs::write(r.0.join("preserved.dat"), exact).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(r.0.join("preserved.dat"), fs::Permissions::from_mode(0o600)).unwrap();
    }

    GitSnapshotEngine::rewind(&r.0, Some(&target.snapshot_id)).unwrap();
    GitSnapshotEngine::undo_rewind(&r.0).unwrap();

    assert_eq!(fs::read(r.0.join("preserved.dat")).unwrap(), exact);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(r.0.join("preserved.dat"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }
}

#[cfg(unix)]
#[test]
fn undo_restores_symlink_type_and_target() {
    use std::os::unix::fs::symlink;

    let r = repo();
    symlink("a.txt", r.0.join("working-link")).unwrap();
    run(&r.0, &["add", "working-link"]);
    run(&r.0, &["commit", "-qm", "add symlink fixture"]);
    let target = GitSnapshotEngine::create_snapshot(&r.0, None).unwrap();

    fs::remove_file(r.0.join("working-link")).unwrap();
    symlink("b.txt", r.0.join("working-link")).unwrap();
    GitSnapshotEngine::rewind(&r.0, Some(&target.snapshot_id)).unwrap();
    GitSnapshotEngine::undo_rewind(&r.0).unwrap();

    assert!(fs::symlink_metadata(r.0.join("working-link"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        fs::read_link(r.0.join("working-link")).unwrap(),
        Path::new("b.txt")
    );
}

#[test]
fn rewind_fails_before_mutation_when_raw_backup_storage_is_unavailable() {
    let r = repo();
    let target = GitSnapshotEngine::create_snapshot(&r.0, None).unwrap();
    let modified = b"working bytes that must remain";
    fs::write(r.0.join("a.txt"), modified).unwrap();
    let backups = r.0.join(".git/devtape/raw-backups");
    fs::write(&backups, b"not a directory").unwrap();

    GitSnapshotEngine::create_snapshot(&r.0, Some("snapshot-only")).unwrap();
    assert!(GitSnapshotEngine::rewind(&r.0, Some(&target.snapshot_id)).is_err());
    assert_eq!(fs::read(r.0.join("a.txt")).unwrap(), modified);
}

#[test]
fn undo_fails_before_mutation_when_raw_backup_is_corrupt() {
    let r = repo();
    let target = GitSnapshotEngine::create_snapshot(&r.0, None).unwrap();
    fs::write(r.0.join("a.txt"), b"pre-rewind bytes").unwrap();
    let outcome = GitSnapshotEngine::rewind(&r.0, Some(&target.snapshot_id)).unwrap();
    let restored_target = fs::read(r.0.join("a.txt")).unwrap();
    let objects =
        r.0.join(".git/devtape/raw-backups")
            .join(outcome.pre_rewind.snapshot_id)
            .join("objects");
    let object = fs::read_dir(objects)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::write(object, b"corrupt").unwrap();

    assert!(GitSnapshotEngine::undo_rewind(&r.0).is_err());
    assert_eq!(fs::read(r.0.join("a.txt")).unwrap(), restored_target);
}
