#![forbid(unsafe_code)]
//! Single-writer SQLite WAL session store and privacy-profile exporter.
mod analysis;
pub use analysis::{
    diff_archives, search_archive, EventCountDelta, GitDiffSummary, HttpExchangeDiff, SearchMatch,
    StreamFilter, TapeDiffReport,
};
use devtape_scrub::{Scrubber, RULESET_VERSION};
use dtp_codec::{
    CoreEvent, EventEnvelope, ExportProfile, StreamChannel, TapeArchive, TapeManifest,
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("SQLite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("codec: {0}")]
    Codec(#[from] dtp_codec::CodecError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("store actor: {0}")]
    Actor(String),
    #[error("session not found: {0}")]
    NotFound(String),
}
impl CoreError {
    /// Whether opening a database failed because its location cannot be written.
    pub fn is_unwritable(&self) -> bool {
        match self {
            Self::Io(e) => {
                e.kind() == std::io::ErrorKind::PermissionDenied
                    || (cfg!(unix) && e.raw_os_error() == Some(30))
            }
            Self::Sql(rusqlite::Error::SqliteFailure(e, _)) => matches!(
                e.code,
                rusqlite::ErrorCode::CannotOpen
                    | rusqlite::ErrorCode::ReadOnly
                    | rusqlite::ErrorCode::PermissionDenied
            ),
            _ => false,
        }
    }
}
type Reply = mpsc::Sender<Result<(), String>>;
enum Message {
    Session(TapeManifest, Reply),
    Event(String, EventEnvelope),
    Archive(TapeArchive, Reply),
    Flush(Reply),
    Close(Reply),
}
struct Inner {
    tx: mpsc::Sender<Message>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        let (tx, rx) = mpsc::channel();
        if self.tx.send(Message::Close(tx)).is_ok() {
            let _ = rx.recv();
        }
        if let Ok(t) = self.thread.get_mut() {
            if let Some(h) = t.take() {
                let _ = h.join();
            }
        }
    }
}
#[derive(Clone)]
pub struct SessionStore {
    inner: Arc<Inner>,
    path: PathBuf,
}
#[derive(Debug, Serialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub os: String,
    pub arch: String,
    pub shell: String,
    pub qos_mode: dtp_codec::QosMode,
    pub redacted_count: u64,
    pub event_count: u64,
}
#[derive(Debug, Serialize)]
pub struct ExportReviewReport {
    pub session_id: String,
    pub profile: ExportProfile,
    pub total_events_stored: usize,
    pub exported_events_count: usize,
    pub excluded_stream_chunks: usize,
    pub excluded_snapshots: usize,
    pub redacted_count: u64,
    pub ruleset_version: String,
    pub extensions: Vec<String>,
    pub local_map_excluded: bool,
}
fn configure(c: &Connection) -> Result<(), CoreError> {
    c.busy_timeout(Duration::from_secs(5))?;
    c.pragma_update(None, "journal_mode", "WAL")?;
    c.pragma_update(None, "synchronous", "NORMAL")?;
    c.pragma_update(None, "foreign_keys", "ON")?;
    c.execute_batch("CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, manifest TEXT NOT NULL); CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL REFERENCES sessions(id), event TEXT NOT NULL); CREATE INDEX IF NOT EXISTS events_session ON events(session_id); CREATE TABLE IF NOT EXISTS session_runtime (session_id TEXT PRIMARY KEY REFERENCES sessions(id), command TEXT NOT NULL DEFAULT '', started_at_ms INTEGER NOT NULL, heartbeat_at_ms INTEGER NOT NULL, completed INTEGER NOT NULL DEFAULT 0);")?;
    Ok(())
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    Stale,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSessionInfo {
    pub session_id: String,
    pub command: String,
    pub started_at_ms: u64,
    pub elapsed_ms: u64,
    pub event_count: u64,
    pub status: SessionStatus,
}

fn heartbeat(conn: &Connection, active: &HashSet<String>) -> Result<(), CoreError> {
    let now = now_ms();
    for id in active {
        conn.execute(
            "UPDATE session_runtime SET heartbeat_at_ms=?1 WHERE session_id=?2 AND completed=0",
            params![now, id],
        )?;
    }
    Ok(())
}

fn flush_batch(
    conn: &mut Connection,
    batch: &mut Vec<(String, EventEnvelope)>,
    active: &mut HashSet<String>,
) -> Result<(), CoreError> {
    if batch.is_empty() {
        return Ok(());
    }
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare("INSERT INTO events(session_id,event) VALUES (?1,?2)")?;
        for (session, event) in batch.iter() {
            stmt.execute(params![session, serde_json::to_string(event)?])?;
            match &event.event {
                CoreEvent::SpanStart { label, .. } => {
                    tx.execute("UPDATE session_runtime SET command=CASE WHEN command='' THEN ?1 ELSE command END, heartbeat_at_ms=?2 WHERE session_id=?3", params![label, now_ms(), session])?;
                }
                CoreEvent::SessionEnd { .. } => {
                    tx.execute("UPDATE session_runtime SET completed=1, heartbeat_at_ms=?1 WHERE session_id=?2", params![now_ms(), session])?;
                    active.remove(session);
                }
                _ => {
                    tx.execute(
                        "UPDATE session_runtime SET heartbeat_at_ms=?1 WHERE session_id=?2",
                        params![now_ms(), session],
                    )?;
                }
            }
        }
    }
    tx.commit()?;
    batch.clear();
    Ok(())
}
fn actor(mut conn: Connection, rx: mpsc::Receiver<Message>, interval: Duration) {
    let mut batch = Vec::new();
    let mut active = HashSet::new();
    let mut failure: Option<String> = None;
    let mut deadline = std::time::Instant::now() + interval;
    loop {
        let received =
            rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()));
        match received {
            Ok(Message::Event(id, event)) => batch.push((id, event)),
            Ok(Message::Session(manifest, reply)) => {
                let result = (|| -> Result<(), CoreError> {
                    if let Some(ref e) = failure {
                        return Err(CoreError::Actor(e.clone()));
                    }
                    flush_batch(&mut conn, &mut batch, &mut active)?;
                    conn.execute(
                        "INSERT INTO sessions(id,manifest) VALUES (?1,?2) ON CONFLICT(id) DO UPDATE SET manifest=excluded.manifest",
                        params![manifest.session_id, serde_json::to_string(&manifest)?],
                    )?;
                    conn.execute("INSERT INTO session_runtime(session_id, command, started_at_ms, heartbeat_at_ms, completed) VALUES (?1, '', ?2, ?2, 0) ON CONFLICT(session_id) DO UPDATE SET heartbeat_at_ms=excluded.heartbeat_at_ms", params![manifest.session_id, now_ms()])?;
                    active.insert(manifest.session_id.clone());
                    Ok(())
                })();
                let _ = reply.send(result.map_err(|e| e.to_string()));
            }
            Ok(Message::Archive(archive, reply)) => {
                let result = (|| -> Result<(), CoreError> {
                    if let Some(ref e) = failure {
                        return Err(CoreError::Actor(e.clone()));
                    }
                    flush_batch(&mut conn, &mut batch, &mut active)?;
                    let tx = conn.transaction()?;
                    tx.execute(
                        "INSERT INTO sessions(id,manifest) VALUES (?1,?2) ON CONFLICT(id) DO UPDATE SET manifest=excluded.manifest",
                        params![archive.manifest.session_id, serde_json::to_string(&archive.manifest)?],
                    )?;
                    let existing = {
                        let mut stmt =
                            tx.prepare("SELECT event FROM events WHERE session_id=?1 ORDER BY id")?;
                        let rows = stmt.query_map([&archive.manifest.session_id], |row| {
                            row.get::<_, String>(0)
                        })?;
                        rows.collect::<Result<Vec<_>, _>>()?
                            .into_iter()
                            .map(|raw| serde_json::from_str::<EventEnvelope>(&raw))
                            .collect::<Result<Vec<_>, _>>()?
                    };
                    let prefix = existing.len() <= archive.events.len()
                        && existing
                            .iter()
                            .zip(&archive.events)
                            .all(|(a, b)| a.event == b.event && a.span_id == b.span_id);
                    let start = if prefix {
                        existing.len()
                    } else {
                        tx.execute(
                            "DELETE FROM events WHERE session_id=?1",
                            [&archive.manifest.session_id],
                        )?;
                        0
                    };
                    {
                        let mut stmt =
                            tx.prepare("INSERT INTO events(session_id,event) VALUES (?1,?2)")?;
                        for event in &archive.events[start..] {
                            stmt.execute(params![
                                archive.manifest.session_id,
                                serde_json::to_string(event)?
                            ])?;
                        }
                    }
                    let command = archive
                        .events
                        .iter()
                        .find_map(|event| match &event.event {
                            CoreEvent::SpanStart { label, .. } => Some(label.as_str()),
                            _ => None,
                        })
                        .unwrap_or("");
                    tx.execute("INSERT INTO session_runtime(session_id,command,started_at_ms,heartbeat_at_ms,completed) VALUES (?1,?2,?3,?3,1) ON CONFLICT(session_id) DO UPDATE SET command=CASE WHEN command='' THEN excluded.command ELSE command END, heartbeat_at_ms=excluded.heartbeat_at_ms, completed=1", params![archive.manifest.session_id, command, now_ms()])?;
                    tx.commit()?;
                    active.remove(&archive.manifest.session_id);
                    Ok(())
                })();
                let _ = reply.send(result.map_err(|e| e.to_string()));
            }
            Ok(Message::Flush(reply)) => {
                if failure.is_none() {
                    if let Err(e) = flush_batch(&mut conn, &mut batch, &mut active) {
                        failure = Some(e.to_string());
                    }
                }
                let _ = reply.send(failure.clone().map_or(Ok(()), Err));
            }
            Ok(Message::Close(reply)) => {
                if failure.is_none() {
                    if let Err(e) = flush_batch(&mut conn, &mut batch, &mut active) {
                        failure = Some(e.to_string());
                    }
                }
                let _ = reply.send(failure.clone().map_or(Ok(()), Err));
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if failure.is_none() {
                    if let Err(e) = flush_batch(&mut conn, &mut batch, &mut active) {
                        failure = Some(e.to_string());
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = flush_batch(&mut conn, &mut batch, &mut active);
                break;
            }
        }
        if std::time::Instant::now() >= deadline {
            if failure.is_none() {
                if let Err(e) = flush_batch(&mut conn, &mut batch, &mut active) {
                    failure = Some(e.to_string());
                }
            }
            if failure.is_none() {
                if let Err(e) = heartbeat(&conn, &active) {
                    failure = Some(e.to_string());
                }
            }
            deadline = std::time::Instant::now() + interval;
        }
    }
}
/// Inspect non-completed recordings through a read-only SQLite connection.
pub fn inspect_sessions(
    path: &Path,
    stale_threshold_ms: u64,
) -> Result<Vec<ActiveSessionInfo>, CoreError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(Duration::from_secs(2))?;
    let has_table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='session_runtime')",
        [],
        |r| r.get(0),
    )?;
    if !has_table {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare("SELECT r.session_id, r.command, r.started_at_ms, r.heartbeat_at_ms, r.completed, (SELECT COUNT(*) FROM events e WHERE e.session_id=r.session_id), EXISTS(SELECT 1 FROM events e WHERE e.session_id=r.session_id AND json_extract(e.event, '$.event.type')='session_end') FROM session_runtime r ORDER BY r.started_at_ms, r.session_id")?;
    let mut rows = stmt.query([])?;
    let mut result = Vec::new();
    let now = now_ms();
    while let Some(row) = rows.next()? {
        let completed: bool = row.get(4)?;
        let ended: bool = row.get(6)?;
        if completed || ended {
            continue;
        }
        let started: u64 = row.get(2)?;
        let heartbeat: u64 = row.get(3)?;
        let command: String = row.get(1)?;
        result.push(ActiveSessionInfo {
            session_id: row.get(0)?,
            command: Scrubber::new().scrub_str(&dtp_codec::sanitize_ansi_for_replay(&command)),
            started_at_ms: started,
            elapsed_ms: now.saturating_sub(started),
            event_count: row.get(5)?,
            status: if now.saturating_sub(heartbeat) <= stale_threshold_ms {
                SessionStatus::Active
            } else {
                SessionStatus::Stale
            },
        });
    }
    Ok(result)
}

/// Resolve the target session ID for `devtape tail` from a read-only SQLite connection.
pub fn resolve_tail_session_id(
    path: &Path,
    explicit_id: Option<&str>,
) -> Result<Option<String>, CoreError> {
    if !path.exists() {
        return Ok(None);
    }
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(Duration::from_secs(2))?;
    let has_sessions: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='sessions')",
        [],
        |r| r.get(0),
    )?;
    if !has_sessions {
        return Ok(None);
    }
    if let Some(id) = explicit_id {
        let found: Option<String> = conn
            .query_row("SELECT id FROM sessions WHERE id=?1", [id], |r| r.get(0))
            .optional()?;
        return Ok(found);
    }
    let has_runtime: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='session_runtime')",
        [],
        |r| r.get(0),
    )?;
    if has_runtime {
        let active: Option<String> = conn
            .query_row(
                "SELECT session_id FROM session_runtime WHERE completed=0 ORDER BY started_at_ms DESC, rowid DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if active.is_some() {
            return Ok(active);
        }
    }
    let latest: Option<String> = conn
        .query_row(
            "SELECT id FROM sessions ORDER BY rowid DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    Ok(latest)
}

/// Read newly committed events for `session_id` with `id > after_rowid` and classify session status.
pub fn fetch_session_events_since(
    path: &Path,
    session_id: &str,
    after_rowid: i64,
    stale_threshold_ms: u64,
) -> Result<(Vec<(i64, EventEnvelope)>, SessionStatus), CoreError> {
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(Duration::from_secs(2))?;
    let mut stmt =
        conn.prepare("SELECT id, event FROM events WHERE session_id=?1 AND id>?2 ORDER BY id ASC")?;
    let mut rows = stmt.query(params![session_id, after_rowid])?;
    let mut events = Vec::new();
    while let Some(row) = rows.next()? {
        let rowid: i64 = row.get(0)?;
        let raw: String = row.get(1)?;
        let env: EventEnvelope = serde_json::from_str(&raw)?;
        events.push((rowid, env));
    }
    let ended_in_events: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM events WHERE session_id=?1 AND json_extract(event, '$.event.type')='session_end')",
        [session_id],
        |r| r.get(0),
    )?;
    let has_runtime: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='session_runtime')",
        [],
        |r| r.get(0),
    )?;
    let status = if ended_in_events {
        SessionStatus::Completed
    } else if has_runtime {
        let runtime_row: Option<(bool, u64)> = conn
            .query_row(
                "SELECT completed, heartbeat_at_ms FROM session_runtime WHERE session_id=?1",
                [session_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match runtime_row {
            Some((true, _)) => SessionStatus::Completed,
            Some((false, hb)) => {
                if now_ms().saturating_sub(hb) <= stale_threshold_ms {
                    SessionStatus::Active
                } else {
                    SessionStatus::Stale
                }
            }
            None => SessionStatus::Completed,
        }
    } else {
        SessionStatus::Completed
    };
    Ok((events, status))
}

fn request(
    tx: &mpsc::Sender<Message>,
    make: impl FnOnce(Reply) -> Message,
) -> Result<(), CoreError> {
    let (reply, rx) = mpsc::channel();
    tx.send(make(reply))
        .map_err(|e| CoreError::Actor(e.to_string()))?;
    rx.recv()
        .map_err(|e| CoreError::Actor(e.to_string()))?
        .map_err(CoreError::Actor)
}
impl SessionStore {
    pub fn open(path: impl AsRef<Path>, interval: Duration) -> Result<Self, CoreError> {
        if interval.is_zero() {
            return Err(CoreError::Actor("batch interval must be positive".into()));
        }
        let path = path.as_ref().to_path_buf();
        if let Some(p) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(p)?;
        }
        let conn = Connection::open(&path)?;
        configure(&conn)?;
        let (tx, rx) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("devtape-sqlite-writer".into())
            .spawn(move || actor(conn, rx, interval))?;
        Ok(Self {
            inner: Arc::new(Inner {
                tx,
                thread: Mutex::new(Some(thread)),
            }),
            path,
        })
    }
    pub fn create_session(&self, manifest: TapeManifest) -> Result<(), CoreError> {
        request(&self.inner.tx, |r| Message::Session(manifest, r))
    }
    pub fn send_event(&self, session_id: &str, event: EventEnvelope) -> Result<(), CoreError> {
        self.inner
            .tx
            .send(Message::Event(session_id.into(), event))
            .map_err(|e| CoreError::Actor(e.to_string()))
    }
    pub fn flush(&self) -> Result<(), CoreError> {
        request(&self.inner.tx, Message::Flush)
    }
    pub fn close(self) -> Result<(), CoreError> {
        let result = request(&self.inner.tx, Message::Close);
        if let Some(thread) = self
            .inner
            .thread
            .lock()
            .map_err(|e| CoreError::Actor(e.to_string()))?
            .take()
        {
            thread
                .join()
                .map_err(|_| CoreError::Actor("writer panicked".into()))?;
        }
        result
    }
    pub fn store_archive(&self, archive: &TapeArchive) -> Result<(), CoreError> {
        request(&self.inner.tx, |r| Message::Archive(archive.clone(), r))
    }
    pub fn sessions(&self) -> Result<Vec<SessionSummary>, CoreError> {
        self.flush()?;
        let conn = Connection::open(&self.path)?;
        let mut st=conn.prepare("SELECT manifest, (SELECT COUNT(*) FROM events WHERE session_id=sessions.id) FROM sessions ORDER BY rowid")?;
        let mut rows = st.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let raw: String = row.get(0)?;
            let m: TapeManifest = serde_json::from_str(&raw)?;
            out.push(SessionSummary {
                session_id: m.session_id,
                os: m.os,
                arch: m.arch,
                shell: m.shell,
                qos_mode: m.qos_mode,
                redacted_count: m.redaction.redacted_count,
                event_count: row.get(1)?,
            });
        }
        Ok(out)
    }
    pub fn export_session(
        &self,
        id: &str,
        profile: ExportProfile,
    ) -> Result<(TapeArchive, ExportReviewReport), CoreError> {
        self.flush()?;
        let conn = Connection::open(&self.path)?;
        let raw: Option<String> = conn
            .query_row("SELECT manifest FROM sessions WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .optional()?;
        let mut manifest: TapeManifest =
            serde_json::from_str(&raw.ok_or_else(|| CoreError::NotFound(id.into()))?)?;
        let mut statement = conn.prepare("SELECT event FROM events WHERE session_id=?1")?;
        let mut rows = statement.query([id])?;
        let mut events = Vec::new();
        while let Some(row) = rows.next()? {
            events.push(serde_json::from_str::<EventEnvelope>(
                &row.get::<_, String>(0)?,
            )?);
        }
        events.sort_by_key(|e| (e.hlc, e.seq));
        let stored = events.len();
        let mut streams = 0;
        let mut snapshots = 0;
        events.retain(|e| {
            let keep = match (&profile, &e.event) {
                (ExportProfile::Full, _) => true,
                (
                    ExportProfile::DiffOnly,
                    CoreEvent::SessionStart { .. }
                    | CoreEvent::SpanStart { .. }
                    | CoreEvent::SpanEnd { .. }
                    | CoreEvent::SessionEnd { .. }
                    | CoreEvent::StateSnapshot { .. },
                ) => true,
                (ExportProfile::DiffOnly, CoreEvent::Extension { extension_id, .. }) => {
                    extension_id == "ext.git.v1" || extension_id == "ext.ci.v1"
                }
                (
                    ExportProfile::TraceOnly,
                    CoreEvent::SessionStart { .. }
                    | CoreEvent::SpanStart { .. }
                    | CoreEvent::SpanEnd { .. }
                    | CoreEvent::SessionEnd { .. }
                    | CoreEvent::DropMarker { .. },
                ) => true,
                _ => false,
            };
            if !keep {
                if matches!(e.event, CoreEvent::StreamChunk { .. }) {
                    streams += 1;
                }
                if matches!(e.event, CoreEvent::StateSnapshot { .. }) {
                    snapshots += 1;
                }
            }
            keep
        });
        let mut scrubber = Scrubber::new();
        // Reassemble each channel before scrubbing so secrets split across events are detected.
        for channel in [
            StreamChannel::Stdin,
            StreamChannel::Stdout,
            StreamChannel::Stderr,
        ] {
            let mut joined = String::new();
            let mut indices = Vec::new();
            for (i, e) in events.iter().enumerate() {
                if let CoreEvent::StreamChunk { channel: c, data } = &e.event {
                    if *c == channel {
                        joined.push_str(data);
                        indices.push(i);
                    }
                }
            }
            if let Some((&last, rest)) = indices.split_last() {
                let cleaned = scrubber.scrub_str(&joined);
                if cleaned != joined {
                    for i in rest {
                        if let CoreEvent::StreamChunk { data, .. } = &mut events[*i].event {
                            data.clear();
                        }
                    }
                    if let CoreEvent::StreamChunk { data, .. } = &mut events[last].event {
                        *data = cleaned;
                    }
                }
            }
        }
        for e in &mut events {
            match &mut e.event {
                CoreEvent::SessionStart {
                    sanitized_cwd,
                    env_fingerprint,
                } => {
                    *sanitized_cwd = scrubber.scrub_str(sanitized_cwd);
                    *env_fingerprint = scrubber.scrub_str(env_fingerprint);
                }
                CoreEvent::SpanStart { kind, label } => {
                    *kind = scrubber.scrub_str(kind);
                    *label = scrubber.scrub_str(label);
                }
                CoreEvent::StateSnapshot {
                    tree_blake3,
                    changed_files,
                } => {
                    *tree_blake3 = scrubber.scrub_str(tree_blake3);
                    for path in changed_files {
                        *path = scrubber.scrub_str(path);
                    }
                }
                CoreEvent::DropMarker { reason, .. } => *reason = scrubber.scrub_str(reason),
                CoreEvent::Extension {
                    extension_id,
                    event_name,
                    payload,
                } => {
                    *extension_id = scrubber.scrub_str(extension_id);
                    *event_name = scrubber.scrub_str(event_name);
                    scrub_json(payload, &mut scrubber);
                }
                _ => {}
            }
            e.span_id = scrubber.scrub_str(&e.span_id);
            if let Some(p) = &mut e.parent_span_id {
                *p = scrubber.scrub_str(p);
            }
        }
        manifest.session_id = scrubber.scrub_str(&manifest.session_id);
        manifest.spec_version = scrubber.scrub_str(&manifest.spec_version);
        manifest.os = scrubber.scrub_str(&manifest.os);
        manifest.arch = scrubber.scrub_str(&manifest.arch);
        manifest.shell = scrubber.scrub_str(&manifest.shell);
        for extension in &mut manifest.extensions {
            *extension = scrubber.scrub_str(extension);
        }
        manifest.export_profile = profile;
        manifest.redaction.local_map_excluded = true;
        manifest.redaction.redacted_count = manifest
            .redaction
            .redacted_count
            .saturating_add(scrubber.redacted_count());
        manifest.redaction.ruleset_version = RULESET_VERSION.into();
        if profile == ExportProfile::TraceOnly {
            manifest.extensions.clear();
        } else if profile == ExportProfile::DiffOnly {
            manifest
                .extensions
                .retain(|e| e == "ext.git.v1" || e == "ext.ci.v1");
        }
        let len = events.len() as u64;
        for (i, e) in events.iter_mut().enumerate() {
            e.seq = i as u64 + 1;
            if let CoreEvent::SessionEnd { total_events, .. } = &mut e.event {
                *total_events = len;
            }
        }
        let review = ExportReviewReport {
            session_id: id.into(),
            profile,
            total_events_stored: stored,
            exported_events_count: events.len(),
            excluded_stream_chunks: streams,
            excluded_snapshots: snapshots,
            redacted_count: manifest.redaction.redacted_count,
            ruleset_version: manifest.redaction.ruleset_version.clone(),
            extensions: manifest.extensions.clone(),
            local_map_excluded: true,
        };
        Ok((TapeArchive::new(manifest, events)?, review))
    }
}
use rusqlite::OptionalExtension;
fn scrub_json(v: &mut serde_json::Value, s: &mut Scrubber) {
    match v {
        serde_json::Value::String(x) => *x = s.scrub_str(x),
        serde_json::Value::Array(a) => {
            for x in a {
                scrub_json(x, s)
            }
        }
        serde_json::Value::Object(o) => {
            let old = std::mem::take(o);
            for (k, mut v) in old {
                scrub_json(&mut v, s);
                o.insert(s.scrub_str(&k), v);
            }
        }
        _ => {}
    }
}
