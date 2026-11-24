#![forbid(unsafe_code)]

//! Zero-stall PTY session recorder for DTP v0.1 (`devtape-pty`).
//!
//! Architecture:
//! - **Hot Path (`< 2 ms` budget):** Dedicated OS reader thread writes raw bytes
//!   directly to the host terminal first, then enqueues a non-blocking copy into
//!   a byte-bounded channel (`16 MiB` default cap).
//! - **Backpressure (`QoS-0 ZeroStall`):** Excess bursts are dropped immediately
//!   without blocking terminal I/O and recorded as normative `CoreEvent::DropMarker`
//!   events.
//! - **Cold Path (Async Collector):** Streams chunks through `OverlapScrubber`,
//!   stamps monotonic `HlcTimestamp` envelopes, and produces a verified `TapeArchive`.

use devtape_scrub::{OverlapScrubber, Scrubber, RULESET_VERSION};
use dtp_codec::{
    CodecError, CoreEvent, EventEnvelope, ExportProfile, HlcTimestamp, QosMode,
    RedactionAttestation, StreamChannel, TapeArchive, TapeManifest,
};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::mpsc;

/// Default bounded channel memory cap (16 MiB) per AGENTS.md §3.4.
pub const DEFAULT_MAX_BUFFER_BYTES: usize = 16 * 1024 * 1024;
/// Default channel message slots.
const DEFAULT_CHANNEL_SLOTS: usize = 4096;
/// PTY hot-path read buffer size (16 KiB).
const PTY_READ_CHUNK_BYTES: usize = 16 * 1024;
/// Default reason emitted in `CoreEvent::DropMarker` when `QoS-0` drops excess bursts.
pub const QOS0_BACKPRESSURE_REASON: &str = "qos0_channel_backpressure";

#[derive(Debug, Error)]
pub enum PtyError {
    #[error("pty error: {0}")]
    Pty(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("codec error: {0}")]
    Codec(#[from] CodecError),
    #[error("record sink: {0}")]
    Sink(String),
    #[error("task join error: {0}")]
    Join(String),
}

/// Receives scrubbed events on the recorder cold path.
pub trait RecordSink: Send + Sync {
    fn on_session_start(&self, manifest: &TapeManifest) -> Result<(), String>;
    fn on_event(&self, session_id: &str, event: &EventEnvelope) -> Result<(), String>;
    fn on_session_update(&self, manifest: &TapeManifest) -> Result<(), String>;
}

/// Configuration for a `devtape record` PTY session.
#[derive(Clone)]
pub struct RecordConfig {
    /// Command and arguments to run inside the PTY. If empty, defaults to the user's shell.
    pub sink: Option<Arc<dyn RecordSink>>,
    pub command: Vec<String>,
    /// Working directory for the child process (defaults to current working directory).
    pub cwd: Option<PathBuf>,
    /// QoS mode: `ZeroStall` (QoS-0, default) or `Lossless` (QoS-1).
    pub qos_mode: QosMode,
    /// Export privacy profile declared in the manifest.
    pub export_profile: ExportProfile,
    /// Maximum queued bytes in the hot-to-cold channel before QoS-0 drops bursts.
    pub max_buffer_bytes: usize,
    /// Environment additions for the child PTY only.
    pub extra_env: Vec<(String, String)>,
    /// Initial terminal rows.
    pub rows: u16,
    /// Initial terminal columns.
    pub cols: u16,
    /// Whether the hot-path reader thread forwards raw output directly to host stdout.
    pub passthrough_stdout: bool,
    /// Optional bytes to feed to the child PTY and capture as stdin.
    pub simulated_stdin: Option<Vec<u8>>,
    /// Forward the host terminal input to the child PTY.
    pub interactive_stdin: bool,
    /// Optional watch channel for live terminal dimensions.
    pub resize_rx: Option<tokio::sync::watch::Receiver<(u16, u16)>>,
}

impl Default for RecordConfig {
    fn default() -> Self {
        Self {
            sink: None,
            command: Vec::new(),
            cwd: None,
            qos_mode: QosMode::ZeroStall,
            export_profile: ExportProfile::Full,
            max_buffer_bytes: DEFAULT_MAX_BUFFER_BYTES,
            extra_env: Vec::new(),
            rows: 24,
            cols: 80,
            passthrough_stdout: true,
            simulated_stdin: None,
            interactive_stdin: false,
            resize_rx: None,
        }
    }
}

/// Completed PTY recording result containing the verified `.tape` archive and child exit status.
#[derive(Debug, Clone)]
pub struct RecordOutcome {
    pub archive: TapeArchive,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub bytes_dropped: u64,
}

/// Internal signal passed from the hot-path PTY reader to the cold-path collector.
#[derive(Debug)]
pub enum PtySignal {
    Chunk {
        channel: StreamChannel,
        data: Vec<u8>,
        hlc: HlcTimestamp,
    },
    Drop {
        bytes_dropped: u64,
        reason: String,
        hlc: HlcTimestamp,
    },
}

/// Non-blocking byte-bounded producer used by the PTY hot path.
#[derive(Clone)]
pub struct PtyProducer {
    tx: mpsc::Sender<PtySignal>,
    qos_mode: QosMode,
    max_buffer_bytes: usize,
    queued_bytes: Arc<AtomicUsize>,
    pending_dropped_bytes: Arc<AtomicU64>,
    budget: Arc<(Mutex<bool>, Condvar)>,
    clocks: Arc<[Mutex<HlcTimestamp>; 3]>,
}

/// Consumer side of the byte-bounded queue processed by the cold-path collector.
pub struct PtyConsumer {
    rx: mpsc::Receiver<PtySignal>,
    queued_bytes: Arc<AtomicUsize>,
    pending_dropped_bytes: Arc<AtomicU64>,
    budget: Arc<(Mutex<bool>, Condvar)>,
}

/// Creates a bounded byte queue enforcing the `max_buffer_bytes` memory cap.
pub fn bounded_byte_queue(
    qos_mode: QosMode,
    max_buffer_bytes: usize,
) -> (PtyProducer, PtyConsumer) {
    let (tx, rx) = mpsc::channel(DEFAULT_CHANNEL_SLOTS);
    let queued_bytes = Arc::new(AtomicUsize::new(0));
    let pending_dropped_bytes = Arc::new(AtomicU64::new(0));
    let budget = Arc::new((Mutex::new(false), Condvar::new()));
    let clocks = Arc::new([
        Mutex::new(HlcTimestamp::now(2)),
        Mutex::new(HlcTimestamp::now(3)),
        Mutex::new(HlcTimestamp::now(4)),
    ]);
    (
        PtyProducer {
            tx,
            qos_mode,
            max_buffer_bytes: max_buffer_bytes.max(1),
            queued_bytes: Arc::clone(&queued_bytes),
            pending_dropped_bytes: Arc::clone(&pending_dropped_bytes),
            budget: Arc::clone(&budget),
            clocks,
        },
        PtyConsumer {
            rx,
            queued_bytes,
            pending_dropped_bytes,
            budget,
        },
    )
}

impl PtyProducer {
    /// Enqueues a stream chunk from the PTY hot path.
    ///
    /// Under `QosMode::ZeroStall`, this method never blocks: if the byte budget
    /// (`max_buffer_bytes`) or channel slot cap is exceeded, the chunk is dropped
    /// immediately and accumulated into `pending_dropped_bytes` for `DropMarker` emission.
    pub fn send_chunk(&self, channel: StreamChannel, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        let len = data.len();
        let index = match channel {
            StreamChannel::Stdout => 0,
            StreamChannel::Stdin => 1,
            StreamChannel::Stderr => 2,
        };
        let hlc = self.clocks[index].lock().unwrap().tick(now_wall_ms());

        match self.qos_mode {
            QosMode::ZeroStall => {
                // Attempt to reserve `len` bytes within `max_buffer_bytes`.
                let mut current = self.queued_bytes.load(Ordering::SeqCst);
                let reserved = loop {
                    let next = current.saturating_add(len);
                    if next > self.max_buffer_bytes {
                        break false;
                    }
                    match self.queued_bytes.compare_exchange_weak(
                        current,
                        next,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => break true,
                        Err(actual) => current = actual,
                    }
                };

                if !reserved {
                    self.pending_dropped_bytes
                        .fetch_add(len as u64, Ordering::SeqCst);
                    return;
                }

                // Attempt to flush any previously accumulated drop count before this chunk.
                self.try_flush_pending_drops();

                if let Err(err) = self.tx.try_send(PtySignal::Chunk { channel, data, hlc }) {
                    // Roll back reservation and account for the dropped chunk.
                    self.queued_bytes.fetch_sub(len, Ordering::SeqCst);
                    if let PtySignal::Chunk { data: dropped, .. } = err.into_inner() {
                        self.pending_dropped_bytes
                            .fetch_add(dropped.len() as u64, Ordering::SeqCst);
                    }
                }
            }
            QosMode::Lossless => {
                let (lock, ready) = &*self.budget;
                let mut closed = lock.lock().unwrap();
                while !*closed {
                    let queued = self.queued_bytes.load(Ordering::SeqCst);
                    if queued == 0
                        || queued
                            .checked_add(len)
                            .is_some_and(|n| n <= self.max_buffer_bytes)
                    {
                        break;
                    }
                    closed = ready.wait(closed).unwrap();
                }
                if *closed {
                    return;
                }
                self.queued_bytes.fetch_add(len, Ordering::SeqCst);
                drop(closed);
                if self
                    .tx
                    .blocking_send(PtySignal::Chunk { channel, data, hlc })
                    .is_err()
                {
                    let _guard = lock.lock().unwrap();
                    self.queued_bytes.fetch_sub(len, Ordering::SeqCst);
                    ready.notify_all();
                }
            }
        }
    }

    /// Best-effort non-blocking flush of any accumulated dropped byte counter into the channel.
    pub fn try_flush_pending_drops(&self) {
        let dropped = self.pending_dropped_bytes.swap(0, Ordering::SeqCst);
        if dropped == 0 {
            return;
        }
        if let Err(err) = self.tx.try_send(PtySignal::Drop {
            bytes_dropped: dropped,
            reason: QOS0_BACKPRESSURE_REASON.to_string(),
            hlc: self.clocks[0].lock().unwrap().tick(now_wall_ms()),
        }) {
            if let PtySignal::Drop { bytes_dropped, .. } = err.into_inner() {
                self.pending_dropped_bytes
                    .fetch_add(bytes_dropped, Ordering::SeqCst);
            }
        }
    }
}

impl PtyConsumer {
    /// Receives the next signal from the queue and releases its reserved byte budget.
    pub async fn recv(&mut self) -> Option<PtySignal> {
        let sig = self.rx.recv().await?;
        if let PtySignal::Chunk { ref data, .. } = sig {
            let _guard = self.budget.0.lock().unwrap();
            self.queued_bytes.fetch_sub(data.len(), Ordering::SeqCst);
            self.budget.1.notify_all();
        }
        Some(sig)
    }

    /// Atomically takes any remaining un-emitted dropped byte count.
    pub fn take_pending_drops(&self) -> u64 {
        self.pending_dropped_bytes.swap(0, Ordering::SeqCst)
    }
}

impl Drop for PtyConsumer {
    fn drop(&mut self) {
        let mut closed = self.budget.0.lock().unwrap();
        *closed = true;
        self.rx.close();
        self.budget.1.notify_all();
    }
}

/// Replaces the user's home directory prefix with `~` and scrubs any embedded secrets.
pub fn sanitize_cwd(cwd: &Path, scrubber: &mut Scrubber) -> String {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    sanitize_cwd_with_home(cwd, home.as_deref(), scrubber)
}

/// Testable helper that sanitizes `cwd` against an explicit `home` path.
pub fn sanitize_cwd_with_home(cwd: &Path, home: Option<&Path>, scrubber: &mut Scrubber) -> String {
    let raw = if let Some(home_dir) = home {
        if let Ok(stripped) = cwd.strip_prefix(home_dir) {
            if stripped.as_os_str().is_empty() {
                "~".to_string()
            } else {
                format!("~/{}", stripped.to_string_lossy().replace('\\', "/"))
            }
        } else {
            cwd.to_string_lossy().into_owned()
        }
    } else {
        cwd.to_string_lossy().into_owned()
    };
    scrubber.scrub_str(&raw)
}

/// Generates a deterministic-length hex identifier (`prefix_<16-hex>`) using Blake3.
fn generate_hex_id(prefix: &str, seed_tag: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let input = format!("{prefix}:{seed_tag}:{now_nanos}:{pid}:{seq}");
    let digest = blake3::hash(input.as_bytes()).to_hex();
    format!("{prefix}_{}", &digest[..16])
}

/// Computes a privacy-safe fingerprint of key non-secret environment traits.
fn compute_env_fingerprint(shell: &str) -> String {
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
    let raw = format!(
        "os={};arch={};shell={};term={}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        shell,
        term
    );
    let digest = blake3::hash(raw.as_bytes()).to_hex();
    digest[..16].to_string()
}

fn default_shell_command() -> Vec<String> {
    if cfg!(windows) {
        vec![std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".into())]
    } else {
        vec![std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())]
    }
}

fn now_wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Tests whether the host can create a native PTY pair.
pub fn probe_pty_support() -> Result<String, PtyError> {
    let _pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| PtyError::Pty(e.to_string()))?;
    Ok("native PTY available (24x80)".into())
}

#[cfg(unix)]
struct RawTerminalGuard(termios::Termios);

#[cfg(unix)]
impl RawTerminalGuard {
    fn enter() -> Result<Self, PtyError> {
        let original = termios::Termios::from_fd(0)?;
        let mut raw = original;
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(0, termios::TCSANOW, &raw)?;
        Ok(Self(original))
    }
}

#[cfg(unix)]
impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        let _ = termios::tcsetattr(0, termios::TCSANOW, &self.0);
    }
}

#[cfg(unix)]
fn parent_terminal_size() -> Option<(u16, u16)> {
    let output = std::process::Command::new("stty")
        .arg("size")
        .stdin(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = std::str::from_utf8(&output.stdout).ok()?;
    let mut values = text.split_whitespace();
    let (rows, cols) = (values.next()?.parse().ok()?, values.next()?.parse().ok()?);
    if rows == 0 || cols == 0 {
        return None;
    }
    Some((rows, cols))
}

#[cfg(not(unix))]
fn parent_terminal_size() -> Option<(u16, u16)> {
    None
}

/// Zero-stall PTY session recorder.
pub struct PtyRecorder;

impl PtyRecorder {
    /// Spawns the configured command inside a cross-platform PTY, forwards output
    /// with `< 2 ms` zero-stall passthrough, scrubs streaming output via `OverlapScrubber`,
    /// and returns a verified DTP v0.1 `TapeArchive`.
    pub async fn record(config: RecordConfig) -> Result<RecordOutcome, PtyError> {
        let start_instant = Instant::now();
        let mut clock = HlcTimestamp::now(1);
        let mut meta_scrubber = Scrubber::new();

        let cmd_vec = if config.command.is_empty() {
            default_shell_command()
        } else {
            config.command.clone()
        };
        let shell_name = cmd_vec
            .first()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let raw_label = cmd_vec.join(" ");
        let scrubbed_label = meta_scrubber.scrub_str(&raw_label);

        let working_dir = match &config.cwd {
            Some(dir) => dir.clone(),
            None => std::env::current_dir()?,
        };
        let sanitized_cwd = sanitize_cwd(&working_dir, &mut meta_scrubber);
        let env_fingerprint = compute_env_fingerprint(&shell_name);

        let session_id = generate_hex_id("sess", &scrubbed_label);
        let root_span_id = generate_hex_id("sp", &session_id);
        let parent_span_id = std::env::var("DTP_SPAN_ID")
            .ok()
            .filter(|s| !s.trim().is_empty());

        let interactive = config.interactive_stdin && config.simulated_stdin.is_none();
        #[cfg(not(unix))]
        if config.interactive_stdin && config.simulated_stdin.is_none() {
            return Err(PtyError::Pty(
                "interactive stdin is not supported on this platform".into(),
            ));
        }
        #[cfg(unix)]
        let _raw_guard = if interactive {
            Some(RawTerminalGuard::enter()?)
        } else {
            None
        };
        let initial_size = if interactive {
            parent_terminal_size()
        } else {
            None
        };
        let (rows, cols) = initial_size.unwrap_or((config.rows, config.cols));
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| PtyError::Pty(e.to_string()))?;

        let mut cmd_builder = CommandBuilder::new(&cmd_vec[0]);
        if cmd_vec.len() > 1 {
            cmd_builder.args(&cmd_vec[1..]);
        }
        cmd_builder.cwd(&working_dir);
        cmd_builder.env("DTP_SPAN_ID", &root_span_id);
        cmd_builder.env("DTP_SESSION_ID", &session_id);
        for (key, value) in &config.extra_env {
            cmd_builder.env(key, value);
        }

        let mut child = pair
            .slave
            .spawn_command(cmd_builder)
            .map_err(|e| PtyError::Pty(e.to_string()))?;

        // Drop slave handle in parent immediately so EOF is delivered when child exits.
        drop(pair.slave);

        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| PtyError::Pty(e.to_string()))?;

        let (producer, mut consumer) = bounded_byte_queue(config.qos_mode, config.max_buffer_bytes);
        let session_active = Arc::new(AtomicBool::new(true));
        let stdin_handle = if let Some(input) = config.simulated_stdin.clone() {
            let mut writer = pair
                .master
                .take_writer()
                .map_err(|e| PtyError::Pty(e.to_string()))?;
            let stdin_producer = producer.clone();
            Some(std::thread::spawn(move || -> Result<(), PtyError> {
                let mut remaining = input.as_slice();
                while !remaining.is_empty() {
                    match writer.write(remaining) {
                        Ok(0) => {
                            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into())
                        }
                        Ok(n) => {
                            stdin_producer
                                .send_chunk(StreamChannel::Stdin, remaining[..n].to_vec());
                            remaining = &remaining[n..];
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e.into()),
                    }
                }
                Ok(())
            }))
        } else if config.interactive_stdin {
            #[cfg(unix)]
            {
                let mut writer = pair
                    .master
                    .take_writer()
                    .map_err(|e| PtyError::Pty(e.to_string()))?;
                let stdin_producer = producer.clone();
                let active = Arc::clone(&session_active);
                Some(std::thread::spawn(move || -> Result<(), PtyError> {
                    let mut input = std::io::stdin();
                    let mut buf = [0u8; 4096];
                    while active.load(Ordering::Acquire) {
                        let mut fds = [filedescriptor::pollfd {
                            fd: 0,
                            events: filedescriptor::POLLIN,
                            revents: 0,
                        }];
                        match filedescriptor::poll(
                            &mut fds,
                            Some(std::time::Duration::from_millis(50)),
                        ) {
                            Ok(0) => continue,
                            Ok(_) => {}
                            Err(e) => return Err(PtyError::Pty(e.to_string())),
                        }
                        if !active.load(Ordering::Acquire) {
                            break;
                        }
                        match input.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                let mut remaining = &buf[..n];
                                while !remaining.is_empty() {
                                    match writer.write(remaining) {
                                        Ok(0) => {
                                            return Err(std::io::Error::from(
                                                std::io::ErrorKind::WriteZero,
                                            )
                                            .into())
                                        }
                                        Ok(written) => {
                                            stdin_producer.send_chunk(
                                                StreamChannel::Stdin,
                                                remaining[..written].to_vec(),
                                            );
                                            remaining = &remaining[written..];
                                        }
                                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                                            continue
                                        }
                                        Err(e) if !active.load(Ordering::Acquire) => {
                                            let _ = e;
                                            return Ok(());
                                        }
                                        Err(e) => return Err(e.into()),
                                    }
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            Err(e) => return Err(e.into()),
                        }
                    }
                    Ok(())
                }))
            }
            #[cfg(not(unix))]
            {
                None
            }
        } else {
            None
        };
        let passthrough = config.passthrough_stdout;

        // Hot-path OS thread: zero-stall terminal passthrough + non-blocking enqueue.
        let reader_handle = std::thread::Builder::new()
            .name("devtape-pty-hot-reader".into())
            .spawn(move || {
                let mut buf = [0u8; PTY_READ_CHUNK_BYTES];
                let mut stdout = std::io::stdout();
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if passthrough {
                                let _ = stdout.write_all(&buf[..n]);
                                let _ = stdout.flush();
                            }
                            producer.send_chunk(StreamChannel::Stdout, buf[..n].to_vec());
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
                producer.try_flush_pending_drops();
            })?;

        // Wait for child process termination on a blocking thread.
        let wait_active = Arc::clone(&session_active);
        let wait_handle = tokio::task::spawn_blocking(move || {
            let result = child.wait();
            wait_active.store(false, Ordering::Release);
            let status = result.map_err(|e| PtyError::Pty(e.to_string()))?;
            Ok::<i32, PtyError>(status.exit_code() as i32)
        });

        // Cold-path event collector: HLC stamping + OverlapScrubber + DropMarker tracking.
        let mut manifest = TapeManifest {
            spec_version: "0.1.0".into(),
            session_id: session_id.clone(),
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            shell: shell_name,
            qos_mode: config.qos_mode,
            export_profile: config.export_profile,
            extensions: Vec::new(),
            redaction: RedactionAttestation {
                ruleset_version: RULESET_VERSION.into(),
                redacted_count: meta_scrubber.redacted_count(),
                local_map_excluded: true,
            },
        };
        if let Some(sink) = &config.sink {
            sink.on_session_start(&manifest).map_err(PtyError::Sink)?;
        }
        let mut events: Vec<EventEnvelope> = Vec::new();
        macro_rules! emit {
            ($event:expr) => {{
                let event = $event;
                if let Some(sink) = &config.sink {
                    sink.on_event(&session_id, &event).map_err(PtyError::Sink)?;
                }
                events.push(event);
            }};
        }
        let mut seq: u64 = 1;
        let mut stdout_scrubber = OverlapScrubber::new();
        let mut stdin_scrubber = OverlapScrubber::new();
        let mut total_bytes_dropped: u64 = 0;

        // 1. SessionStart
        emit!(EventEnvelope {
            seq,
            hlc: clock.tick(now_wall_ms()),
            span_id: root_span_id.clone(),
            parent_span_id: parent_span_id.clone(),
            event: CoreEvent::SessionStart {
                sanitized_cwd,
                env_fingerprint,
            },
        });
        seq += 1;

        // 2. SpanStart
        emit!(EventEnvelope {
            seq,
            hlc: clock.tick(now_wall_ms()),
            span_id: root_span_id.clone(),
            parent_span_id: parent_span_id.clone(),
            event: CoreEvent::SpanStart {
                kind: "command".into(),
                label: scrubbed_label,
            },
        });
        seq += 1;

        // 3. Drain streaming chunks and drop markers.
        let mut pair_master = Some(pair.master);
        let mut wait_handle = Some(wait_handle);
        let mut child_exit_code: Option<i32> = None;
        let mut resize_rx = config.resize_rx.clone();
        let mut last_parent_size = initial_size;
        let mut size_interval = tokio::time::interval(std::time::Duration::from_millis(250));
        loop {
            let signal = tokio::select! {
                signal = consumer.recv() => match signal { Some(signal) => signal, None => break },
                res = async { wait_handle.as_mut().expect("guarded").await }, if cfg!(windows) && wait_handle.is_some() => {
                    wait_handle = None;
                    child_exit_code = Some(res.map_err(|e| PtyError::Join(e.to_string()))??);
                    // Give ConPTY a brief moment to flush buffered child output, then drop
                    // the master handle so the blocking reader thread receives EOF on Windows.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    pair_master = None;
                    continue;
                },
                _ = size_interval.tick(), if interactive => {
                    let measured = tokio::task::spawn_blocking(parent_terminal_size).await.map_err(|e| PtyError::Join(e.to_string()))?;
                    if let Some((rows, cols)) = measured {
                        if last_parent_size != Some((rows, cols)) {
                            if let Some(ref master) = pair_master {
                                master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 }).map_err(|e| PtyError::Pty(e.to_string()))?;
                            }
                            emit!(EventEnvelope { seq, hlc: clock.tick(now_wall_ms()), span_id: root_span_id.clone(), parent_span_id: parent_span_id.clone(), event: CoreEvent::Extension { extension_id: "ext.pty.v1".into(), event_name: "terminal_resize".into(), payload: serde_json::json!({"rows": rows, "cols": cols}) } });
                            seq += 1;
                            last_parent_size = Some((rows, cols));
                        }
                    }
                    continue;
                },
                result = async { resize_rx.as_mut().expect("guarded").changed().await }, if resize_rx.is_some() => {
                    if result.is_err() { resize_rx = None; continue; }
                    let (rows, cols) = *resize_rx.as_mut().expect("guarded").borrow_and_update();
                    if let Some(ref master) = pair_master {
                        master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 }).map_err(|e| PtyError::Pty(e.to_string()))?;
                    }
                    emit!(EventEnvelope { seq, hlc: clock.tick(now_wall_ms()), span_id: root_span_id.clone(), parent_span_id: parent_span_id.clone(), event: CoreEvent::Extension { extension_id: "ext.pty.v1".into(), event_name: "terminal_resize".into(), payload: serde_json::json!({"rows": rows, "cols": cols}) } });
                    seq += 1;
                    continue;
                }
            };
            match signal {
                PtySignal::Chunk { channel, data, hlc } => {
                    clock.merge(hlc, now_wall_ms());
                    let text = String::from_utf8_lossy(&data);
                    let emit = match channel {
                        StreamChannel::Stdin => stdin_scrubber.push_chunk(&text),
                        StreamChannel::Stdout | StreamChannel::Stderr => {
                            stdout_scrubber.push_chunk(&text)
                        }
                    };
                    if !emit.is_empty() {
                        emit!(EventEnvelope {
                            seq,
                            hlc: clock.tick(now_wall_ms()),
                            span_id: root_span_id.clone(),
                            parent_span_id: parent_span_id.clone(),
                            event: CoreEvent::StreamChunk {
                                channel,
                                data: emit,
                            },
                        });
                        seq += 1;
                    }
                }
                PtySignal::Drop {
                    bytes_dropped,
                    reason,
                    hlc,
                } => {
                    clock.merge(hlc, now_wall_ms());
                    total_bytes_dropped = total_bytes_dropped.saturating_add(bytes_dropped);
                    emit!(EventEnvelope {
                        seq,
                        hlc: clock.tick(now_wall_ms()),
                        span_id: root_span_id.clone(),
                        parent_span_id: parent_span_id.clone(),
                        event: CoreEvent::DropMarker {
                            bytes_dropped,
                            reason,
                        },
                    });
                    seq += 1;
                }
            }
        }

        reader_handle
            .join()
            .map_err(|_| PtyError::Join("PTY reader panicked".into()))?;
        if let Some(handle) = stdin_handle {
            handle
                .join()
                .map_err(|_| PtyError::Join("PTY stdin writer panicked".into()))??;
        }
        drop(pair_master);
        let exit_code = match child_exit_code {
            Some(code) => code,
            None => wait_handle
                .expect("wait_handle present")
                .await
                .map_err(|e| PtyError::Join(e.to_string()))??,
        };

        // Flush any remaining drop count that could not fit into the channel before close.
        let trailing_drops = consumer.take_pending_drops();
        if trailing_drops > 0 {
            total_bytes_dropped = total_bytes_dropped.saturating_add(trailing_drops);
            emit!(EventEnvelope {
                seq,
                hlc: clock.tick(now_wall_ms()),
                span_id: root_span_id.clone(),
                parent_span_id: parent_span_id.clone(),
                event: CoreEvent::DropMarker {
                    bytes_dropped: trailing_drops,
                    reason: QOS0_BACKPRESSURE_REASON.to_string(),
                },
            });
            seq += 1;
        }

        // Flush remaining tail buffers from OverlapScrubber.
        let rem_stdin = stdin_scrubber.finish();
        if !rem_stdin.is_empty() {
            emit!(EventEnvelope {
                seq,
                hlc: clock.tick(now_wall_ms()),
                span_id: root_span_id.clone(),
                parent_span_id: parent_span_id.clone(),
                event: CoreEvent::StreamChunk {
                    channel: StreamChannel::Stdin,
                    data: rem_stdin,
                },
            });
            seq += 1;
        }

        let rem_stdout = stdout_scrubber.finish();
        if !rem_stdout.is_empty() {
            emit!(EventEnvelope {
                seq,
                hlc: clock.tick(now_wall_ms()),
                span_id: root_span_id.clone(),
                parent_span_id: parent_span_id.clone(),
                event: CoreEvent::StreamChunk {
                    channel: StreamChannel::Stdout,
                    data: rem_stdout,
                },
            });
            seq += 1;
        }

        let duration_ms = start_instant.elapsed().as_millis() as u64;

        // 4. SpanEnd
        emit!(EventEnvelope {
            seq,
            hlc: clock.tick(now_wall_ms()),
            span_id: root_span_id.clone(),
            parent_span_id: parent_span_id.clone(),
            event: CoreEvent::SpanEnd {
                exit_code,
                duration_ms,
            },
        });
        seq += 1;

        // 5. SessionEnd
        let total_events = seq;
        emit!(EventEnvelope {
            seq,
            hlc: clock.tick(now_wall_ms()),
            span_id: root_span_id,
            parent_span_id,
            event: CoreEvent::SessionEnd {
                total_events,
                duration_ms,
            },
        });

        let total_redacted = meta_scrubber.redacted_count()
            + stdout_scrubber.redacted_count()
            + stdin_scrubber.redacted_count();

        manifest.redaction.redacted_count = total_redacted;
        if let Some(sink) = &config.sink {
            sink.on_session_update(&manifest).map_err(PtyError::Sink)?;
        }

        let archive = TapeArchive::new(manifest, events)?;
        Ok(RecordOutcome {
            archive,
            exit_code,
            duration_ms,
            bytes_dropped: total_bytes_dropped,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cross_platform_shell_cmd(script: &str) -> Vec<String> {
        if cfg!(windows) {
            vec!["cmd.exe".into(), "/C".into(), script.into()]
        } else {
            vec!["sh".into(), "-c".into(), script.into()]
        }
    }

    #[tokio::test]
    async fn records_command_and_propagates_dtp_span_id() {
        let cmd = if cfg!(windows) {
            cross_platform_shell_cmd("echo SPAN=%DTP_SPAN_ID%")
        } else {
            cross_platform_shell_cmd("echo SPAN=$DTP_SPAN_ID")
        };

        let config = RecordConfig {
            command: cmd,
            passthrough_stdout: false,
            ..RecordConfig::default()
        };

        let outcome = PtyRecorder::record(config).await.expect("record succeeds");
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.bytes_dropped, 0);

        let events = &outcome.archive.events;
        assert!(events.len() >= 5);

        let root_span_id = &events[0].span_id;
        assert!(root_span_id.starts_with("sp_"));
        assert!(matches!(events[0].event, CoreEvent::SessionStart { .. }));
        assert!(matches!(events[1].event, CoreEvent::SpanStart { .. }));
        assert!(matches!(
            events[events.len() - 2].event,
            CoreEvent::SpanEnd { exit_code: 0, .. }
        ));
        assert!(matches!(
            events[events.len() - 1].event,
            CoreEvent::SessionEnd { .. }
        ));

        let combined_stdout: String = events
            .iter()
            .filter_map(|e| match &e.event {
                CoreEvent::StreamChunk {
                    channel: StreamChannel::Stdout,
                    data,
                } => Some(data.as_str()),
                _ => None,
            })
            .collect();

        assert!(
            combined_stdout.contains(&format!("SPAN={root_span_id}")),
            "expected child output to contain propagated DTP_SPAN_ID ({root_span_id}), got: {combined_stdout:?}"
        );

        // Verify roundtrip encoding and decoding of the recorded archive.
        let encoded = outcome.archive.encode().expect("encode .tape");
        let decoded = TapeArchive::decode(&encoded).expect("decode .tape");
        assert_eq!(decoded, outcome.archive);
    }

    #[tokio::test]
    async fn scrubs_secrets_in_pty_stream() {
        let cmd = cross_platform_shell_cmd(
            "echo TOKEN=sk-proj-1234567890abcdefghijklmno && echo AWS=AKIAIOSFODNN7EXAMPLE",
        );

        let config = RecordConfig {
            command: cmd,
            passthrough_stdout: false,
            ..RecordConfig::default()
        };

        let outcome = PtyRecorder::record(config).await.expect("record succeeds");
        let combined_stdout: String = outcome
            .archive
            .events
            .iter()
            .filter_map(|e| match &e.event {
                CoreEvent::StreamChunk { data, .. } => Some(data.as_str()),
                _ => None,
            })
            .collect();

        assert!(!combined_stdout.contains("sk-proj-1234567890abcdefghijklmno"));
        assert!(!combined_stdout.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(combined_stdout.contains("<DTP:REDACTED:API_KEY:"));
        assert!(combined_stdout.contains("<DTP:REDACTED:AWS_KEY:"));
        assert!(outcome.archive.manifest.redaction.redacted_count >= 2);
        assert!(outcome.archive.manifest.redaction.local_map_excluded);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn captures_and_scrubs_simulated_stdin() {
        let secret = "sk-proj-1234567890abcdefghijklmno";
        let config = RecordConfig {
            command: cross_platform_shell_cmd("stty -echo; read line"),
            simulated_stdin: Some(format!("{secret}\n").into_bytes()),
            passthrough_stdout: false,
            ..RecordConfig::default()
        };
        let outcome = PtyRecorder::record(config).await.unwrap();
        let stdin: String = outcome
            .archive
            .events
            .iter()
            .filter_map(|e| match &e.event {
                CoreEvent::StreamChunk {
                    channel: StreamChannel::Stdin,
                    data,
                } => Some(data.as_str()),
                _ => None,
            })
            .collect();
        assert!(!stdin.contains(secret));
        assert!(stdin.contains("<DTP:REDACTED:API_KEY:"));
        assert!(outcome.archive.manifest.redaction.redacted_count >= 1);
    }

    #[tokio::test]
    async fn qos0_backpressure_emits_drop_marker_without_stalling() {
        // Cap the buffer at 256 bytes and push 4 KiB before the consumer reads.
        let (producer, mut consumer) = bounded_byte_queue(QosMode::ZeroStall, 256);

        for _ in 0..16 {
            producer.send_chunk(StreamChannel::Stdout, vec![b'A'; 256]);
        }

        // First 256-byte chunk fits; the remaining 15 chunks (3840 bytes) must be dropped without blocking.
        let first = consumer.recv().await.expect("first chunk delivered");
        match first {
            PtySignal::Chunk { data, .. } => assert_eq!(data.len(), 256),
            other => panic!("expected first signal to be Chunk, got {other:?}"),
        }

        // Now flush pending drops and verify the exact drop count (15 * 256 = 3840 bytes).
        producer.try_flush_pending_drops();
        drop(producer);

        let mut total_dropped = consumer.take_pending_drops();
        while let Some(sig) = consumer.recv().await {
            if let PtySignal::Drop { bytes_dropped, .. } = sig {
                total_dropped += bytes_dropped;
            }
        }
        assert_eq!(total_dropped, 15 * 256);
    }

    #[tokio::test]
    async fn lossless_budget_blocks_and_delivers_all_chunks() {
        let (producer, mut consumer) = bounded_byte_queue(QosMode::Lossless, 4);
        let queued = Arc::clone(&producer.queued_bytes);
        let (sent_tx, sent_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            producer.send_chunk(StreamChannel::Stdout, vec![1; 4]);
            sent_tx.send(1).unwrap();
            producer.send_chunk(StreamChannel::Stdin, vec![2; 2]);
            sent_tx.send(2).unwrap();
            producer.send_chunk(StreamChannel::Stdout, vec![3; 8]);
            sent_tx.send(3).unwrap();
        });
        assert_eq!(
            sent_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap(),
            1
        );
        assert!(sent_rx
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());
        assert_eq!(queued.load(Ordering::SeqCst), 4);
        let first = consumer.recv().await.unwrap();
        assert!(
            matches!(first, PtySignal::Chunk { data, hlc: HlcTimestamp { node_id: 2, .. }, .. } if data.len() == 4)
        );
        assert_eq!(
            sent_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap(),
            2
        );
        assert!(sent_rx
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());
        assert!(
            matches!(consumer.recv().await.unwrap(), PtySignal::Chunk { data, hlc: HlcTimestamp { node_id: 3, .. }, .. } if data.len() == 2)
        );
        assert_eq!(
            sent_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap(),
            3
        );
        assert!(
            matches!(consumer.recv().await.unwrap(), PtySignal::Chunk { data, .. } if data.len() == 8)
        );
        handle.join().unwrap();
        assert_eq!(consumer.take_pending_drops(), 0);
        assert!(consumer.recv().await.is_none());
    }

    #[test]
    fn closing_consumer_unblocks_lossless_producer() {
        let (producer, consumer) = bounded_byte_queue(QosMode::Lossless, 1);
        producer.send_chunk(StreamChannel::Stdout, vec![1]);
        let handle =
            std::thread::spawn(move || producer.send_chunk(StreamChannel::Stdout, vec![2]));
        drop(consumer);
        handle.join().unwrap();
    }

    #[test]
    fn sanitizes_home_directory_in_cwd() {
        let mut scrubber = Scrubber::new();
        let home = Path::new("/Users/alice");
        let project = Path::new("/Users/alice/projects/devtape");
        assert_eq!(
            sanitize_cwd_with_home(project, Some(home), &mut scrubber),
            "~/projects/devtape"
        );
    }
}
