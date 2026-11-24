#![forbid(unsafe_code)]
//! Single-writer SQLite WAL session store and privacy-profile exporter.
use devtape_scrub::{Scrubber, RULESET_VERSION};
use dtp_codec::{
    CoreEvent, EventEnvelope, ExportProfile, StreamChannel, TapeArchive, TapeManifest,
};
use rusqlite::{params, Connection};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::Duration,
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
    c.execute_batch("CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, manifest TEXT NOT NULL); CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL REFERENCES sessions(id), event TEXT NOT NULL); CREATE INDEX IF NOT EXISTS events_session ON events(session_id);")?;
    Ok(())
}
fn flush_batch(
    conn: &mut Connection,
    batch: &mut Vec<(String, EventEnvelope)>,
) -> Result<(), CoreError> {
    if batch.is_empty() {
        return Ok(());
    }
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare("INSERT INTO events(session_id,event) VALUES (?1,?2)")?;
        for (session, event) in batch.iter() {
            stmt.execute(params![session, serde_json::to_string(event)?])?;
        }
    }
    tx.commit()?;
    batch.clear();
    Ok(())
}
fn actor(mut conn: Connection, rx: mpsc::Receiver<Message>, interval: Duration) {
    let mut batch = Vec::new();
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
                    flush_batch(&mut conn, &mut batch)?;
                    conn.execute(
                        "INSERT INTO sessions(id,manifest) VALUES (?1,?2) ON CONFLICT(id) DO UPDATE SET manifest=excluded.manifest",
                        params![manifest.session_id, serde_json::to_string(&manifest)?],
                    )?;
                    Ok(())
                })();
                let _ = reply.send(result.map_err(|e| e.to_string()));
            }
            Ok(Message::Archive(archive, reply)) => {
                let result = (|| -> Result<(), CoreError> {
                    if let Some(ref e) = failure {
                        return Err(CoreError::Actor(e.clone()));
                    }
                    flush_batch(&mut conn, &mut batch)?;
                    let tx = conn.transaction()?;
                    tx.execute(
                        "INSERT INTO sessions(id,manifest) VALUES (?1,?2) ON CONFLICT(id) DO UPDATE SET manifest=excluded.manifest",
                        params![archive.manifest.session_id, serde_json::to_string(&archive.manifest)?],
                    )?;
                    tx.execute(
                        "DELETE FROM events WHERE session_id=?1",
                        [&archive.manifest.session_id],
                    )?;
                    {
                        let mut stmt =
                            tx.prepare("INSERT INTO events(session_id,event) VALUES (?1,?2)")?;
                        for event in &archive.events {
                            stmt.execute(params![
                                archive.manifest.session_id,
                                serde_json::to_string(event)?
                            ])?;
                        }
                    }
                    tx.commit()?;
                    Ok(())
                })();
                let _ = reply.send(result.map_err(|e| e.to_string()));
            }
            Ok(Message::Flush(reply)) => {
                if failure.is_none() {
                    if let Err(e) = flush_batch(&mut conn, &mut batch) {
                        failure = Some(e.to_string());
                    }
                }
                let _ = reply.send(failure.clone().map_or(Ok(()), Err));
            }
            Ok(Message::Close(reply)) => {
                if failure.is_none() {
                    if let Err(e) = flush_batch(&mut conn, &mut batch) {
                        failure = Some(e.to_string());
                    }
                }
                let _ = reply.send(failure.clone().map_or(Ok(()), Err));
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if failure.is_none() {
                    if let Err(e) = flush_batch(&mut conn, &mut batch) {
                        failure = Some(e.to_string());
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = flush_batch(&mut conn, &mut batch);
                break;
            }
        }
        if std::time::Instant::now() >= deadline {
            if failure.is_none() {
                if let Err(e) = flush_batch(&mut conn, &mut batch) {
                    failure = Some(e.to_string());
                }
            }
            deadline = std::time::Instant::now() + interval;
        }
    }
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
