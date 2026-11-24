#![forbid(unsafe_code)]
//! Non-destructive Git shadow snapshots and guarded working-tree restoration.
use dtp_codec::{validate_safe_relative_path, CoreEvent};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GitError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Git failed: {0}")]
    Git(String),
    #[error("invalid or unsafe snapshot: {0}")]
    Unsafe(String),
    #[error("snapshot not found: {0}")]
    NotFound(String),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowSnapshot {
    pub snapshot_id: String,
    pub label: Option<String>,
    pub git_tree_oid: String,
    pub tree_blake3: String,
    pub changed_files: Vec<String>,
    pub head_oid: Option<String>,
    pub branch: Option<String>,
}
impl ShadowSnapshot {
    pub fn to_state_snapshot_event(&self) -> CoreEvent {
        CoreEvent::StateSnapshot {
            tree_blake3: self.tree_blake3.clone(),
            changed_files: self.changed_files.clone(),
        }
    }
    pub fn to_extension_event(&self) -> CoreEvent {
        CoreEvent::Extension {
            extension_id: "ext.git.v1".into(),
            event_name: "shadow_snapshot".into(),
            payload: serde_json::json!({"snapshot_id":self.snapshot_id,"git_tree_oid":self.git_tree_oid,"head_oid":self.head_oid,"branch":self.branch}),
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct RewindOutcome {
    pub target: ShadowSnapshot,
    pub pre_rewind: ShadowSnapshot,
}
#[derive(Default, Serialize, Deserialize)]
struct State {
    latest_snapshot_id: Option<String>,
    last_pre_rewind_id: Option<String>,
    pre_rewind_stack: Vec<String>,
}
struct Repo {
    root: PathBuf,
    git_dir: PathBuf,
    dir: PathBuf,
}
struct TempIndex(PathBuf);
impl Drop for TempIndex {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _ = fs::remove_file(self.0.with_extension("lock"));
    }
}
fn unique() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}
fn git(root: &Path, args: &[&str], index: Option<&Path>) -> Result<Vec<u8>, GitError> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(root)
        .args(args)
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE");
    if let Some(index) = index {
        cmd.env("GIT_INDEX_FILE", index);
    }
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(GitError::Git(
            String::from_utf8_lossy(&out.stderr).trim().into(),
        ));
    }
    Ok(out.stdout)
}
fn text(bytes: Vec<u8>) -> Result<String, GitError> {
    String::from_utf8(bytes)
        .map(|s| s.trim_end_matches(['\r', '\n']).to_owned())
        .map_err(|_| GitError::Unsafe("non-UTF-8 Git output".into()))
}
fn normalize_canonical(p: PathBuf) -> PathBuf {
    #[cfg(windows)]
    if let Some(s) = p.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
        return PathBuf::from(s);
    }
    p
}
fn resolve(repo: &Path) -> Result<Repo, GitError> {
    let root = normalize_canonical(fs::canonicalize(text(git(
        repo,
        &["rev-parse", "--show-toplevel"],
        None,
    )?)?)?);
    let raw = text(git(&root, &["rev-parse", "--git-dir"], None)?)?;
    let p = PathBuf::from(raw);
    let git_dir = normalize_canonical(fs::canonicalize(if p.is_absolute() {
        p
    } else {
        root.join(p)
    })?);
    let dir = git_dir.join("devtape");
    fs::create_dir_all(dir.join("snapshots"))?;
    fs::create_dir_all(dir.join("cas"))?;
    Ok(Repo { root, git_dir, dir })
}
fn temp_index(repo: &Repo, copy: bool) -> Result<TempIndex, GitError> {
    let p = repo.dir.join(format!("tmp-index-{}", unique()));
    if copy && repo.git_dir.join("index").exists() {
        fs::copy(repo.git_dir.join("index"), &p)?;
    }
    Ok(TempIndex(p))
}
fn state(repo: &Repo) -> Result<State, GitError> {
    let path = repo.dir.join("state.json");
    if path.exists() {
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    } else {
        Ok(State::default())
    }
}
fn save_state(repo: &Repo, s: &State) -> Result<(), GitError> {
    let p = repo.dir.join(format!("state-{}.tmp", unique()));
    fs::write(&p, serde_json::to_vec_pretty(s)?)?;
    fs::rename(p, repo.dir.join("state.json"))?;
    Ok(())
}
fn safe_id(id: &str) -> Result<(), GitError> {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err(GitError::Unsafe("invalid snapshot id".into()));
    }
    Ok(())
}
fn load(repo: &Repo, id: &str) -> Result<ShadowSnapshot, GitError> {
    safe_id(id)?;
    let p = repo.dir.join("snapshots").join(format!("{id}.json"));
    if !p.exists() {
        return Err(GitError::NotFound(id.into()));
    }
    let s: ShadowSnapshot = serde_json::from_slice(&fs::read(p)?)?;
    if s.snapshot_id != id
        || !s.git_tree_oid.bytes().all(|b| b.is_ascii_hexdigit())
        || !(s.git_tree_oid.len() == 40 || s.git_tree_oid.len() == 64)
    {
        return Err(GitError::Unsafe("invalid snapshot metadata".into()));
    }
    Ok(s)
}
#[derive(Debug)]
struct Entry {
    mode: String,
    oid: String,
    path: String,
}
fn tree(repo: &Repo, oid: &str) -> Result<Vec<Entry>, GitError> {
    let bytes = git(
        &repo.root,
        &["ls-tree", "-r", "-z", "--full-tree", oid],
        None,
    )?;
    let mut result = Vec::new();
    for record in bytes.split(|b| *b == 0).filter(|x| !x.is_empty()) {
        let tab = record
            .iter()
            .position(|b| *b == b'\t')
            .ok_or_else(|| GitError::Unsafe("invalid tree entry".into()))?;
        let (header, rest) = record.split_at(tab);
        let path = &rest[1..];
        let path = String::from_utf8(path.to_vec())
            .map_err(|_| GitError::Unsafe("non-UTF-8 path".into()))?;
        validate_safe_relative_path(&path).map_err(|e| GitError::Unsafe(e.to_string()))?;
        let header = std::str::from_utf8(header)
            .map_err(|_| GitError::Unsafe("invalid tree header".into()))?;
        let parts: Vec<_> = header.split_whitespace().collect();
        if parts.len() != 3
            || parts[1] != "blob"
            || !["100644", "100755", "120000"].contains(&parts[0])
        {
            return Err(GitError::Unsafe(format!("unsupported tree entry {path}")));
        }
        result.push(Entry {
            mode: parts[0].into(),
            oid: parts[2].into(),
            path,
        });
    }
    Ok(result)
}
pub const MIN_CHUNK: usize = 16 * 1024;
pub const AVG_CHUNK: usize = 64 * 1024;
pub const MAX_CHUNK: usize = 256 * 1024;
pub struct FastCdcChunker;
impl FastCdcChunker {
    pub fn chunks(data: &[u8]) -> Vec<&[u8]> {
        let mut result = Vec::new();
        let mut start = 0;
        while start < data.len() {
            let end = (start + MAX_CHUNK).min(data.len());
            let mut i = (start + MIN_CHUNK).min(end);
            let mut hash = 0u64;
            while i < end {
                let mut x = data[i] as u64 + 0x9e3779b97f4a7c15;
                x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
                x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
                let gear = x ^ (x >> 31);
                hash = hash.wrapping_shl(1).wrapping_add(gear);
                i += 1;
                let mask = if i - start < AVG_CHUNK {
                    (1u64 << 17) - 1
                } else {
                    (1u64 << 15) - 1
                };
                if hash & mask == 0 {
                    break;
                }
            }
            result.push(&data[start..i]);
            start = i;
        }
        result
    }
}
fn store_chunks(repo: &Repo, data: &[u8]) -> Result<(), GitError> {
    for chunk in FastCdcChunker::chunks(data) {
        let name = blake3::hash(chunk).to_hex().to_string();
        let path = repo.dir.join("cas").join(format!("{name}.zst"));
        if !path.exists() {
            let compressed = zstd::stream::encode_all(chunk, 3)?;
            let temporary = repo.dir.join("cas").join(format!(".tmp-{}", unique()));
            let result = (|| -> Result<(), GitError> {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temporary)?;
                file.write_all(&compressed)?;
                file.sync_all()?;
                fs::rename(&temporary, &path)?;
                Ok(())
            })();
            if result.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            result?;
        }
    }
    Ok(())
}
fn snapshot(repo: &Repo, label: Option<&str>, pre: bool) -> Result<ShadowSnapshot, GitError> {
    let index = temp_index(repo, true)?;
    git(
        &repo.root,
        &["-c", "core.autocrlf=false", "add", "-A", "--", "."],
        Some(&index.0),
    )?;
    let oid = text(git(&repo.root, &["write-tree"], Some(&index.0))?)?;
    let entries = tree(repo, &oid)?;
    let mut hasher = blake3::Hasher::new();
    for e in &entries {
        let data = git(&repo.root, &["cat-file", "blob", &e.oid], None)?;
        let digest = blake3::hash(&data);
        for part in [
            e.path.as_bytes(),
            e.mode.as_bytes(),
            digest.as_bytes().as_slice(),
        ] {
            hasher.update(&(part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        if data.len() > AVG_CHUNK {
            store_chunks(repo, &data)?;
        }
    }
    let head = git(&repo.root, &["rev-parse", "--verify", "HEAD"], None)
        .ok()
        .map(text)
        .transpose()?;
    let branch = git(&repo.root, &["symbolic-ref", "--short", "-q", "HEAD"], None)
        .ok()
        .map(text)
        .transpose()?;
    let mut changed = if let Some(ref head) = head {
        git(
            &repo.root,
            &[
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "-r",
                "-z",
                head,
                &oid,
            ],
            None,
        )?
    } else {
        git(
            &repo.root,
            &["ls-tree", "-r", "--name-only", "-z", &oid],
            None,
        )?
    };
    if let Some(ref head) = head {
        changed.extend(git(
            &repo.root,
            &["diff", "--cached", "--name-only", "-z", head, "--"],
            None,
        )?);
    }
    let mut changed_files = BTreeSet::new();
    for part in changed.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let p = String::from_utf8(part.to_vec())
            .map_err(|_| GitError::Unsafe("non-UTF-8 changed path".into()))?;
        validate_safe_relative_path(&p).map_err(|e| GitError::Unsafe(e.to_string()))?;
        changed_files.insert(p);
    }
    let s = ShadowSnapshot {
        snapshot_id: unique(),
        label: label.map(str::to_owned),
        git_tree_oid: oid,
        tree_blake3: hasher.finalize().to_hex().to_string(),
        changed_files: changed_files.into_iter().collect(),
        head_oid: head,
        branch,
    };
    // Keep tree objects reachable so Git garbage collection cannot prune snapshots.
    let reference = format!("refs/devtape/snapshots/{}", s.snapshot_id);
    git(
        &repo.root,
        &["update-ref", &reference, &s.git_tree_oid],
        None,
    )?;
    fs::write(
        repo.dir
            .join("snapshots")
            .join(format!("{}.json", s.snapshot_id)),
        serde_json::to_vec_pretty(&s)?,
    )?;
    if !pre {
        let mut st = state(repo)?;
        st.latest_snapshot_id = Some(s.snapshot_id.clone());
        save_state(repo, &st)?;
    }
    Ok(s)
}
struct OperationLock(PathBuf);
impl OperationLock {
    fn acquire(repo: &Repo) -> Result<Self, GitError> {
        let path = repo.dir.join("operation.lock");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| GitError::Unsafe(format!("cannot acquire snapshot lock: {e}")))?;
        Ok(Self(path))
    }
}
impl Drop for OperationLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn index_bytes(repo: &Repo) -> Result<Option<Vec<u8>>, GitError> {
    match fs::read(repo.git_dir.join("index")) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
fn check_ancestors(root: &Path, path: &str) -> Result<(), GitError> {
    let mut parent = root.to_path_buf();
    let p = Path::new(path);
    if let Some(prefix) = p.parent() {
        for component in prefix.components() {
            parent.push(component);
            match fs::symlink_metadata(&parent) {
                Ok(m) if m.file_type().is_symlink() => {
                    return Err(GitError::Unsafe(format!("symlink parent: {path}")))
                }
                Ok(m) if !m.is_dir() => {
                    return Err(GitError::Unsafe(format!("non-directory parent: {path}")))
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(())
}
fn restore(repo: &Repo, target: &ShadowSnapshot, current: &ShadowSnapshot) -> Result<(), GitError> {
    let old = tree(repo, &current.git_tree_oid)?;
    let new = tree(repo, &target.git_tree_oid)?;
    let old_set: BTreeSet<_> = old.iter().map(|e| e.path.as_str()).collect();
    let new_set: BTreeSet<_> = new.iter().map(|e| e.path.as_str()).collect();
    for e in old.iter().chain(new.iter()) {
        check_ancestors(&repo.root, &e.path)?;
    }
    for e in &new {
        let path = repo.root.join(&e.path);
        if !old_set.contains(e.path.as_str()) && fs::symlink_metadata(&path).is_ok() {
            return Err(GitError::Unsafe(format!(
                "unmanaged path would be overwritten: {}",
                e.path
            )));
        }
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if meta.is_dir() {
                return Err(GitError::Unsafe(format!(
                    "directory would be overwritten: {}",
                    e.path
                )));
            }
        }
    }
    let index_before = index_bytes(repo)?;
    let index = temp_index(repo, false)?;
    git(
        &repo.root,
        &["read-tree", &target.git_tree_oid],
        Some(&index.0),
    )?;
    for e in &old {
        if !new_set.contains(e.path.as_str()) {
            let path = repo.root.join(&e.path);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            let mut parent = path.parent();
            while let Some(p) = parent {
                if p == repo.root {
                    break;
                }
                if fs::remove_dir(p).is_err() {
                    break;
                }
                parent = p.parent();
            }
        }
    }
    git(
        &repo.root,
        &["-c", "core.autocrlf=false", "checkout-index", "-a", "-f"],
        Some(&index.0),
    )?;
    if index_before != index_bytes(repo)? {
        return Err(GitError::Unsafe(
            "real Git index changed concurrently".into(),
        ));
    }
    Ok(())
}
pub struct GitSnapshotEngine;
impl GitSnapshotEngine {
    pub fn create_snapshot(
        repo_dir: &Path,
        label: Option<&str>,
    ) -> Result<ShadowSnapshot, GitError> {
        let repo = resolve(repo_dir)?;
        let _lock = OperationLock::acquire(&repo)?;
        snapshot(&repo, label, false)
    }
    pub fn rewind(repo_dir: &Path, target_id: Option<&str>) -> Result<RewindOutcome, GitError> {
        let repo = resolve(repo_dir)?;
        let _lock = OperationLock::acquire(&repo)?;
        let mut st = state(&repo)?;
        let id = target_id
            .map(str::to_owned)
            .or(st.latest_snapshot_id.clone())
            .ok_or_else(|| GitError::NotFound("latest snapshot".into()))?;
        let target = load(&repo, &id)?;
        let backup = snapshot(&repo, Some("pre-rewind"), true)?;
        st.pre_rewind_stack.push(backup.snapshot_id.clone());
        st.last_pre_rewind_id = Some(backup.snapshot_id.clone());
        save_state(&repo, &st)?;
        restore(&repo, &target, &backup)?;
        Ok(RewindOutcome {
            target,
            pre_rewind: backup,
        })
    }
    pub fn undo_rewind(repo_dir: &Path) -> Result<ShadowSnapshot, GitError> {
        let repo = resolve(repo_dir)?;
        let _lock = OperationLock::acquire(&repo)?;
        let mut st = state(&repo)?;
        let id = st
            .pre_rewind_stack
            .last()
            .cloned()
            .ok_or_else(|| GitError::NotFound("pre-rewind snapshot".into()))?;
        let target = load(&repo, &id)?;
        let current = snapshot(&repo, Some("pre-undo"), true)?;
        restore(&repo, &target, &current)?;
        st.pre_rewind_stack.pop();
        st.last_pre_rewind_id = st.pre_rewind_stack.last().cloned();
        save_state(&repo, &st)?;
        Ok(target)
    }
}
