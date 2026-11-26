#![forbid(unsafe_code)]
//! Non-destructive Git shadow snapshots and guarded working-tree restoration.
use dtp_codec::{validate_safe_relative_path, CoreEvent};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    io::{Read, Write},
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
fn create_private_dir(path: &Path) -> Result<(), GitError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(GitError::Unsafe(format!(
            "private backup path is not a directory: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
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

const RAW_BACKUP_VERSION: u32 = 1;
const MAX_RAW_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawFileKind {
    Regular,
    Symlink,
    SymlinkDirectory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBackupEntry {
    path: String,
    kind: RawFileKind,
    object_blake3: String,
    size: u64,
    unix_mode: Option<u32>,
    readonly: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBackupManifest {
    version: u32,
    snapshot_id: String,
    platform: String,
    entries: Vec<RawBackupEntry>,
}

struct RawBackup {
    directory: PathBuf,
    entries: Vec<RawBackupEntry>,
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

fn open_no_follow(path: &Path) -> Result<fs::File, GitError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(not(any(unix, windows)))]
    return Err(GitError::Unsafe(
        "byte-exact backups are unsupported on this platform".into(),
    ));
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(GitError::Unsafe(format!(
            "raw backup source is not a regular file: {}",
            path.display()
        )));
    }
    Ok(file)
}

fn same_metadata(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        return before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.mode() == after.mode()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec();
    }
    #[cfg(not(unix))]
    {
        before.file_type().is_file() == after.file_type().is_file()
            && before.file_type().is_symlink() == after.file_type().is_symlink()
            && before.len() == after.len()
            && before.permissions().readonly() == after.permissions().readonly()
            && before.modified().ok() == after.modified().ok()
    }
}

fn os_string_bytes(value: OsString) -> Result<Vec<u8>, GitError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        return Ok(value.into_vec());
    }
    #[cfg(windows)]
    {
        return value
            .into_string()
            .map(String::into_bytes)
            .map_err(|_| GitError::Unsafe("non-UTF-8 Windows symlink target".into()));
    }
    #[cfg(not(any(unix, windows)))]
    Err(GitError::Unsafe(
        "byte-exact backups are unsupported on this platform".into(),
    ))
}

fn bytes_os_string(value: &[u8]) -> Result<OsString, GitError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        return Ok(OsString::from_vec(value.to_vec()));
    }
    #[cfg(windows)]
    {
        return String::from_utf8(value.to_vec())
            .map(OsString::from)
            .map_err(|_| GitError::Unsafe("invalid Windows symlink target backup".into()));
    }
    #[cfg(not(any(unix, windows)))]
    Err(GitError::Unsafe(
        "byte-exact backups are unsupported on this platform".into(),
    ))
}

fn read_raw_source(
    repo: &Repo,
    path: &str,
) -> Result<(RawFileKind, Vec<u8>, Option<u32>, bool), GitError> {
    check_ancestors(&repo.root, path)?;
    let absolute = repo.root.join(path);
    let before = fs::symlink_metadata(&absolute)?;
    if before.file_type().is_symlink() {
        let target = fs::read_link(&absolute)?;
        let after = fs::symlink_metadata(&absolute)?;
        if !same_metadata(&before, &after) {
            return Err(GitError::Unsafe(format!(
                "raw backup source changed while reading: {path}"
            )));
        }
        #[cfg(windows)]
        let kind = {
            use std::os::windows::fs::FileTypeExt;
            if before.file_type().is_symlink_dir() {
                RawFileKind::SymlinkDirectory
            } else {
                RawFileKind::Symlink
            }
        };
        #[cfg(not(windows))]
        let kind = RawFileKind::Symlink;
        return Ok((kind, os_string_bytes(target.into_os_string())?, None, false));
    }
    if !before.is_file() {
        return Err(GitError::Unsafe(format!(
            "unsupported raw backup file type: {path}"
        )));
    }
    let mut file = open_no_follow(&absolute)?;
    let opened = file.metadata()?;
    if !same_metadata(&before, &opened) {
        return Err(GitError::Unsafe(format!(
            "raw backup source changed before opening: {path}"
        )));
    }
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let opened_after = file.metadata()?;
    let path_after = fs::symlink_metadata(&absolute)?;
    if !same_metadata(&opened, &opened_after)
        || !same_metadata(&opened_after, &path_after)
        || opened_after.len() != data.len() as u64
    {
        return Err(GitError::Unsafe(format!(
            "raw backup source changed while reading: {path}"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened_after.nlink() != 1 {
            return Err(GitError::Unsafe(format!(
                "hard-linked raw backup source is unsupported: {path}"
            )));
        }
    }
    #[cfg(unix)]
    let unix_mode = {
        use std::os::unix::fs::MetadataExt;
        Some(opened_after.mode() & 0o7777)
    };
    #[cfg(not(unix))]
    let unix_mode = None;
    Ok((
        RawFileKind::Regular,
        data,
        unix_mode,
        opened_after.permissions().readonly(),
    ))
}

fn open_private_new(path: &Path) -> Result<fs::File, GitError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn store_raw_object(objects: &Path, data: &[u8]) -> Result<String, GitError> {
    let digest = blake3::hash(data).to_hex().to_string();
    let path = objects.join(format!("{digest}.zst"));
    if !path.exists() {
        let compressed = zstd::stream::encode_all(data, 3)?;
        let mut file = open_private_new(&path)?;
        file.write_all(&compressed)?;
        file.sync_all()?;
    }
    Ok(digest)
}

fn create_raw_backup(repo: &Repo, snapshot: &ShadowSnapshot) -> Result<(), GitError> {
    let backups = repo.dir.join("raw-backups");
    create_private_dir(&backups)?;
    let final_path = backups.join(&snapshot.snapshot_id);
    if final_path.exists() {
        return Err(GitError::Unsafe("raw backup already exists".into()));
    }
    let temporary = backups.join(format!(".tmp-{}", unique()));
    create_private_dir(&temporary)?;
    let result = (|| -> Result<(), GitError> {
        let objects = temporary.join("objects");
        create_private_dir(&objects)?;
        let mut entries = Vec::new();
        for tree_entry in tree(repo, &snapshot.git_tree_oid)? {
            let (kind, data, unix_mode, readonly) = read_raw_source(repo, &tree_entry.path)?;
            let object_blake3 = store_raw_object(&objects, &data)?;
            entries.push(RawBackupEntry {
                path: tree_entry.path,
                kind,
                object_blake3,
                size: data.len() as u64,
                unix_mode,
                readonly,
            });
        }
        let manifest = RawBackupManifest {
            version: RAW_BACKUP_VERSION,
            snapshot_id: snapshot.snapshot_id.clone(),
            platform: std::env::consts::OS.into(),
            entries,
        };
        let mut file = open_private_new(&temporary.join("manifest.json"))?;
        file.write_all(&serde_json::to_vec_pretty(&manifest)?)?;
        file.sync_all()?;
        fs::rename(&temporary, final_path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, GitError> {
    let mut file = open_no_follow(path)?.take(maximum + 1);
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    if data.len() as u64 > maximum {
        return Err(GitError::Unsafe(format!(
            "raw backup file exceeds size limit: {}",
            path.display()
        )));
    }
    Ok(data)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn load_raw_object(backup: &Path, digest: &str, expected_size: u64) -> Result<Vec<u8>, GitError> {
    if !valid_digest(digest) {
        return Err(GitError::Unsafe("invalid raw backup digest".into()));
    }
    let file = open_no_follow(&backup.join("objects").join(format!("{digest}.zst")))?;
    let limit = expected_size
        .checked_add(1)
        .ok_or_else(|| GitError::Unsafe("raw backup size overflow".into()))?;
    let mut decoder = zstd::stream::read::Decoder::new(file)?.take(limit);
    let mut data = Vec::new();
    decoder.read_to_end(&mut data)?;
    if data.len() as u64 != expected_size || blake3::hash(&data).to_hex().to_string() != digest {
        return Err(GitError::Unsafe(
            "raw backup object failed verification".into(),
        ));
    }
    Ok(data)
}

fn load_raw_backup(repo: &Repo, snapshot: &ShadowSnapshot) -> Result<RawBackup, GitError> {
    safe_id(&snapshot.snapshot_id)?;
    let backups = repo.dir.join("raw-backups");
    let backups_metadata = fs::symlink_metadata(&backups)?;
    if !backups_metadata.is_dir() || backups_metadata.file_type().is_symlink() {
        return Err(GitError::Unsafe("invalid raw backup root".into()));
    }
    let backup = backups.join(&snapshot.snapshot_id);
    let metadata = fs::symlink_metadata(&backup)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(GitError::Unsafe("invalid raw backup directory".into()));
    }
    let objects_metadata = fs::symlink_metadata(backup.join("objects"))?;
    if !objects_metadata.is_dir() || objects_metadata.file_type().is_symlink() {
        return Err(GitError::Unsafe(
            "invalid raw backup object directory".into(),
        ));
    }
    let manifest: RawBackupManifest = serde_json::from_slice(&read_bounded_file(
        &backup.join("manifest.json"),
        MAX_RAW_MANIFEST_BYTES,
    )?)?;
    if manifest.version != RAW_BACKUP_VERSION
        || manifest.snapshot_id != snapshot.snapshot_id
        || manifest.platform != std::env::consts::OS
    {
        return Err(GitError::Unsafe("invalid raw backup manifest".into()));
    }
    let expected_paths: BTreeSet<_> = tree(repo, &snapshot.git_tree_oid)?
        .into_iter()
        .map(|entry| entry.path)
        .collect();
    let mut actual_paths = BTreeSet::new();
    let mut result = Vec::new();
    for entry in manifest.entries {
        validate_safe_relative_path(&entry.path).map_err(|e| GitError::Unsafe(e.to_string()))?;
        if !actual_paths.insert(entry.path.clone()) {
            return Err(GitError::Unsafe("duplicate raw backup path".into()));
        }
        #[cfg(unix)]
        if matches!(entry.kind, RawFileKind::Regular) {
            match entry.unix_mode {
                Some(mode) if mode & !0o7777 == 0 => {}
                _ => return Err(GitError::Unsafe("invalid raw backup mode".into())),
            }
        }
        #[cfg(not(unix))]
        if entry.unix_mode.is_some() {
            return Err(GitError::Unsafe("foreign raw backup mode".into()));
        }
        let data = load_raw_object(&backup, &entry.object_blake3, entry.size)?;
        if !matches!(entry.kind, RawFileKind::Regular) {
            if data.is_empty() {
                return Err(GitError::Unsafe("empty raw symlink target".into()));
            }
            bytes_os_string(data.as_slice())?;
        }
        result.push(entry);
    }
    if actual_paths != expected_paths {
        return Err(GitError::Unsafe(
            "raw backup paths do not match safety snapshot".into(),
        ));
    }
    for path in &actual_paths {
        let mut parent = Path::new(path).parent();
        while let Some(value) = parent {
            if value.as_os_str().is_empty() {
                break;
            }
            let value = value
                .to_str()
                .ok_or_else(|| GitError::Unsafe("non-UTF-8 raw backup path".into()))?;
            if actual_paths.contains(value) {
                return Err(GitError::Unsafe("conflicting raw backup paths".into()));
            }
            parent = Path::new(value).parent();
        }
    }
    Ok(RawBackup {
        directory: backup,
        entries: result,
    })
}

fn restore_git_tree(
    repo: &Repo,
    target: &ShadowSnapshot,
    current: &ShadowSnapshot,
) -> Result<(), GitError> {
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

fn remove_file_and_empty_parents(repo: &Repo, path: &Path) -> Result<(), GitError> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut parent = path.parent();
    while let Some(candidate) = parent {
        if candidate == repo.root {
            break;
        }
        if fs::remove_dir(candidate).is_err() {
            break;
        }
        parent = candidate.parent();
    }
    Ok(())
}

fn create_raw_parent(repo: &Repo, path: &str) -> Result<(), GitError> {
    check_ancestors(&repo.root, path)?;
    let absolute = repo.root.join(path);
    if let Some(parent) = absolute.parent() {
        fs::create_dir_all(parent)?;
    }
    check_ancestors(&repo.root, path)
}

fn restore_regular_file(path: &Path, entry: &RawBackupEntry, data: &[u8]) -> Result<(), GitError> {
    let mut file = open_private_new(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = entry
            .unix_mode
            .ok_or_else(|| GitError::Unsafe("missing raw backup mode".into()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(windows)]
    {
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_readonly(entry.readonly);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn restore_symlink(path: &Path, entry: &RawBackupEntry, data: &[u8]) -> Result<(), GitError> {
    let target = PathBuf::from(bytes_os_string(data)?);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, path)?;
    }
    #[cfg(windows)]
    match entry.kind {
        RawFileKind::SymlinkDirectory => std::os::windows::fs::symlink_dir(target, path)?,
        RawFileKind::Symlink => std::os::windows::fs::symlink_file(target, path)?,
        RawFileKind::Regular => return Err(GitError::Unsafe("invalid raw symlink type".into())),
    }
    #[cfg(not(any(unix, windows)))]
    return Err(GitError::Unsafe(
        "byte-exact backups are unsupported on this platform".into(),
    ));
    Ok(())
}

fn restore_raw_backup(
    repo: &Repo,
    target: &RawBackup,
    current: &ShadowSnapshot,
) -> Result<(), GitError> {
    let old = tree(repo, &current.git_tree_oid)?;
    let old_set: BTreeSet<_> = old.iter().map(|entry| entry.path.as_str()).collect();
    let target_set: BTreeSet<_> = target
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    for path in old
        .iter()
        .map(|entry| entry.path.as_str())
        .chain(target_set.iter().copied())
    {
        check_ancestors(&repo.root, path)?;
    }
    for entry in &target.entries {
        let path = repo.root.join(&entry.path);
        if !old_set.contains(entry.path.as_str()) && fs::symlink_metadata(&path).is_ok() {
            return Err(GitError::Unsafe(format!(
                "unmanaged path would be overwritten: {}",
                entry.path
            )));
        }
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if metadata.is_dir() {
                return Err(GitError::Unsafe(format!(
                    "directory would be overwritten: {}",
                    entry.path
                )));
            }
        }
    }
    let index_before = index_bytes(repo)?;
    for entry in &old {
        if !target_set.contains(entry.path.as_str()) {
            remove_file_and_empty_parents(repo, &repo.root.join(&entry.path))?;
        }
    }
    for entry in &target.entries {
        let data = load_raw_object(&target.directory, &entry.object_blake3, entry.size)?;
        let path = repo.root.join(&entry.path);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        create_raw_parent(repo, &entry.path)?;
        match entry.kind {
            RawFileKind::Regular => restore_regular_file(&path, entry, &data)?,
            RawFileKind::Symlink | RawFileKind::SymlinkDirectory => {
                restore_symlink(&path, entry, &data)?
            }
        }
    }
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
        create_raw_backup(&repo, &backup)?;
        st.pre_rewind_stack.push(backup.snapshot_id.clone());
        st.last_pre_rewind_id = Some(backup.snapshot_id.clone());
        save_state(&repo, &st)?;
        restore_git_tree(&repo, &target, &backup)?;
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
        let raw_backup = load_raw_backup(&repo, &target)?;
        let current = snapshot(&repo, Some("pre-undo"), true)?;
        restore_raw_backup(&repo, &raw_backup, &current)?;
        st.pre_rewind_stack.pop();
        st.last_pre_rewind_id = st.pre_rewind_stack.last().cloned();
        save_state(&repo, &st)?;
        Ok(target)
    }
}
