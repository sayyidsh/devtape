#![forbid(unsafe_code)]

mod ci;

use clap::{Parser, Subcommand};
use devtape_pty::{PtyRecorder, RecordConfig};
use devtape_scrub::{OverlapScrubber, RULESET_VERSION};
use dtp_codec::{
    CoreEvent, EventEnvelope, ExportProfile, HlcTimestamp, QosMode, RedactionAttestation,
    StreamChannel, TapeArchive, TapeManifest,
};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "devtape",
    version,
    about = "Reference CLI for the DevTape Protocol (DTP v0.1)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// View a tape in a local read-only browser.
    View {
        path: PathBuf,
        #[arg(long, default_value_t = 0)]
        port: u16,
    },
    /// Serve read-only MCP tools for a tape over stdio.
    Mcp {
        #[arg(long)]
        tape: PathBuf,
    },
    /// Record an interactive shell or command inside a zero-stall DTP v0.1 PTY session.
    Record {
        /// Output .tape archive path.
        #[arg(short, long, default_value = "session.tape")]
        out: PathBuf,
        /// SQLite session database path.
        #[arg(long)]
        db: Option<PathBuf>,
        /// QoS mode: zero-stall (QoS-0) or lossless (QoS-1).
        #[arg(long, default_value = "zero-stall")]
        qos: String,
        /// Maximum in-memory channel buffer in bytes before QoS-0 drops excess bursts.
        #[arg(long, default_value_t = devtape_pty::DEFAULT_MAX_BUFFER_BYTES)]
        max_buffer_bytes: usize,
        /// Capture HTTP exchanges using a child-only loopback proxy.
        #[arg(long)]
        net: bool,
        /// Command and arguments to execute inside the PTY (defaults to $SHELL).
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    /// List active and stale recordings.
    Ps {
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Stream events from an active or stored SQLite WAL recording session.
    Tail {
        /// Specific session ID to tail (defaults to the latest session if omitted).
        session_id: Option<String>,
        /// Select the most recent active or recorded session.
        #[arg(long)]
        latest: bool,
        /// Follow the session live as new events are committed to SQLite WAL.
        #[arg(short, long)]
        follow: bool,
        /// Filter event stream: all, pty, http, or git.
        #[arg(long, default_value = "all")]
        filter: String,
        /// Emit newline-delimited JSON event envelopes.
        #[arg(long)]
        json: bool,
        /// SQLite session database path.
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Compare two DTP v0.1 .tape archives deterministically.
    Diff {
        a: PathBuf,
        b: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Search across .tape archives or local stored sessions.
    Search {
        query: String,
        paths: Vec<PathBuf>,
        #[arg(long)]
        regex: bool,
        #[arg(long, default_value = "all")]
        stream: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// List stored sessions.
    Sessions {
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Export a stored session with a privacy profile.
    Export {
        session_id: String,
        #[arg(long, default_value = "full")]
        profile: String,
        #[arg(long, default_value = "tape")]
        format: String,
        #[arg(long)]
        review: bool,
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Capture the current Git working tree using a private index.
    Snapshot {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        label: Option<String>,
    },
    /// Restore a snapshot after making a safety snapshot.
    Rewind {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        to: Option<String>,
    },
    /// Restore the most recent pre-rewind snapshot.
    UndoRewind {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },
    /// Generate a valid sample DTP v0.1 .tape archive to test the codec pipeline.
    DemoTape {
        #[arg(long, default_value = "sample.tape")]
        out: PathBuf,
    },
    /// Inspect a .tape file's manifest, redaction attestation, and event timeline.
    Inspect { path: PathBuf },
    /// Check the local recording environment.
    Doctor,
    /// Read stdin through the sliding-window secret scrubber and print the sanitized output.
    ScrubCheck,
}

fn parse_qos_mode(raw: &str) -> Result<QosMode, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "zero-stall" | "zerostall" | "qos0" | "qos-0" => Ok(QosMode::ZeroStall),
        "lossless" | "qos1" | "qos-1" => Ok(QosMode::Lossless),
        other => Err(format!(
            "unsupported --qos mode '{other}' (expected 'zero-stall' or 'lossless')"
        )),
    }
}

fn resolve_db_path(explicit: Option<PathBuf>) -> io::Result<PathBuf> {
    if let Some(path) = explicit.or_else(|| std::env::var_os("DEVTAPE_DB").map(PathBuf::from)) {
        return Ok(path);
    }
    Ok(std::env::current_dir()?.join(".devtape/sessions.db"))
}

fn event_matches_filter(event: &CoreEvent, filter: devtape_core::StreamFilter) -> bool {
    match filter {
        devtape_core::StreamFilter::All => true,
        devtape_core::StreamFilter::Pty => {
            matches!(
                event,
                CoreEvent::StreamChunk { .. }
                    | CoreEvent::DropMarker { .. }
                    | CoreEvent::SpanStart { .. }
                    | CoreEvent::SpanEnd { .. }
            ) || matches!(
                event,
                CoreEvent::Extension { extension_id, .. } if extension_id == "ext.pty.v1"
            )
        }
        devtape_core::StreamFilter::Http => matches!(
            event,
            CoreEvent::Extension { extension_id, .. } if extension_id == "ext.http.v1"
        ),
        devtape_core::StreamFilter::Git => {
            matches!(event, CoreEvent::StateSnapshot { .. })
                || matches!(
                    event,
                    CoreEvent::Extension { extension_id, .. } if extension_id == "ext.git.v1"
                )
        }
    }
}

async fn run_tail(
    path: &Path,
    explicit_id: Option<&str>,
    follow: bool,
    filter: devtape_core::StreamFilter,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let wait_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let target_id = loop {
        if let Some(id) = devtape_core::resolve_tail_session_id(path, explicit_id)? {
            break id;
        }
        if !follow || std::time::Instant::now() >= wait_deadline {
            return Err("no matching session found to tail".into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    };

    let mut after_rowid: i64 = 0;
    let mut seen: std::collections::BTreeSet<(HlcTimestamp, &'static str)> =
        std::collections::BTreeSet::new();
    let mut sanitizers: std::collections::BTreeMap<
        (String, u8),
        (dtp_codec::AnsiReplaySanitizer, StreamChannel),
    > = std::collections::BTreeMap::new();
    let mut last_seq: u64 = 0;
    let mut last_hlc: Option<HlcTimestamp> = None;
    let mut last_parent: Option<String> = None;

    loop {
        let (rows, status) =
            devtape_core::fetch_session_events_since(path, &target_id, after_rowid, 3_000)?;
        let mut saw_end = false;
        for (rowid, mut env) in rows {
            after_rowid = rowid;
            let tag = match &env.event {
                CoreEvent::SessionStart { .. } => "session_start",
                CoreEvent::SpanStart { .. } => "span_start",
                CoreEvent::StreamChunk { .. } => "stream_chunk",
                CoreEvent::StateSnapshot { .. } => "state_snapshot",
                CoreEvent::SpanEnd { .. } => "span_end",
                CoreEvent::SessionEnd { .. } => "session_end",
                CoreEvent::DropMarker { .. } => "drop_marker",
                CoreEvent::Extension { .. } => "extension",
            };
            if !seen.insert((env.hlc, tag)) {
                continue;
            }
            last_seq = env.seq;
            last_hlc = Some(env.hlc);
            last_parent = env.parent_span_id.clone();
            if matches!(env.event, CoreEvent::SessionEnd { .. }) {
                saw_end = true;
            }

            match &mut env.event {
                CoreEvent::StreamChunk { channel, data } => {
                    let ch_idx = match channel {
                        StreamChannel::Stdin => 0,
                        StreamChannel::Stdout => 1,
                        StreamChannel::Stderr => 2,
                    };
                    let entry = sanitizers
                        .entry((env.span_id.clone(), ch_idx))
                        .or_insert_with(|| (dtp_codec::AnsiReplaySanitizer::new(), *channel));
                    *data = entry.0.push_chunk(data);
                    if data.is_empty() {
                        continue;
                    }
                }
                CoreEvent::SpanStart { label, .. } => {
                    *label = dtp_codec::sanitize_ansi_for_replay(label);
                }
                _ => {}
            }

            if !event_matches_filter(&env.event, filter) {
                continue;
            }

            if json {
                println!("{}", serde_json::to_string(&env)?);
                io::stdout().flush()?;
            } else {
                match &env.event {
                    CoreEvent::StreamChunk { data, .. } => {
                        print!("{data}");
                        io::stdout().flush()?;
                    }
                    CoreEvent::DropMarker {
                        bytes_dropped,
                        reason,
                    } => {
                        println!("[drop_marker] {bytes_dropped} bytes dropped ({reason})");
                        io::stdout().flush()?;
                    }
                    CoreEvent::StateSnapshot {
                        tree_blake3,
                        changed_files,
                    } => {
                        println!(
                            "[git_snapshot] tree_blake3={tree_blake3} files={}",
                            changed_files.join(",")
                        );
                        io::stdout().flush()?;
                    }
                    CoreEvent::Extension {
                        extension_id,
                        event_name,
                        payload,
                    } => {
                        if filter != devtape_core::StreamFilter::All
                            || extension_id == "ext.http.v1"
                            || extension_id == "ext.git.v1"
                            || extension_id == "ext.ci.v1"
                        {
                            println!("[{extension_id}:{event_name}] {payload}");
                            io::stdout().flush()?;
                        }
                    }
                    _ => {}
                }
            }
        }

        if !follow || saw_end || status != devtape_core::SessionStatus::Active {
            break;
        }

        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    }

    if filter.allows_pty() {
        for ((span_id, _), (mut sanitizer, channel)) in sanitizers {
            let rem = sanitizer.finish();
            if !rem.is_empty() {
                if json {
                    last_seq += 1;
                    let env = EventEnvelope {
                        seq: last_seq,
                        hlc: last_hlc.unwrap_or_else(|| HlcTimestamp::now(1)),
                        span_id,
                        parent_span_id: last_parent.clone(),
                        event: CoreEvent::StreamChunk { channel, data: rem },
                    };
                    println!("{}", serde_json::to_string(&env)?);
                } else {
                    print!("{rem}");
                }
                io::stdout().flush()?;
            }
        }
    }
    Ok(())
}

fn print_diff_report(a: &Path, b: &Path, report: &devtape_core::TapeDiffReport) {
    println!(
        "DevTape Diff: {} ({}) vs {} ({})",
        a.display(),
        report.session_a,
        b.display(),
        report.session_b
    );
    println!(
        "Exit Code: {:?} -> {:?} (changed: {})",
        report.exit_code_a, report.exit_code_b, report.exit_code_changed
    );
    println!(
        "Duration:  {} ms -> {} ms (delta: {:+} ms)",
        report.duration_ms_a, report.duration_ms_b, report.duration_delta_ms
    );
    println!(
        "Events:    {} -> {} (delta: {:+})",
        report.total_events_a, report.total_events_b, report.total_events_delta
    );
    for (kind, counts) in &report.event_counts {
        println!(
            "  - {:<22} {} -> {} ({:+})",
            kind, counts.a, counts.b, counts.delta
        );
    }
    println!(
        "Git State: tree_blake3 {:?} -> {:?} (changed: {}, +{} / -{} files)",
        report.git.tree_blake3_a,
        report.git.tree_blake3_b,
        report.git.changed,
        report.git.added_files.len(),
        report.git.removed_files.len()
    );
    if !report.http.is_empty() {
        println!("HTTP Exchanges ({}):", report.http.len());
        for h in &report.http {
            println!(
                "  - {} {} : status {:?} -> {:?} (changed: {})",
                h.method, h.url, h.status_a, h.status_b, h.status_changed
            );
        }
    }
}

fn open_store(
    explicit: Option<PathBuf>,
) -> Result<devtape_core::SessionStore, devtape_core::CoreError> {
    let interval = std::time::Duration::from_millis(300);
    if let Some(path) = explicit.or_else(|| std::env::var_os("DEVTAPE_DB").map(PathBuf::from)) {
        return devtape_core::SessionStore::open(path, interval);
    }
    let path = std::env::current_dir()?.join(".devtape/sessions.db");
    match devtape_core::SessionStore::open(path, interval) {
        Ok(store) => Ok(store),
        Err(e) if e.is_unwritable() => {
            let fallback = std::env::temp_dir().join("devtape/sessions.db");
            eprintln!(
                "[devtape] database location is unwritable; using {}",
                fallback.display()
            );
            devtape_core::SessionStore::open(fallback, interval)
        }
        Err(e) => Err(e),
    }
}

struct StoreSink(devtape_core::SessionStore);

impl devtape_pty::RecordSink for StoreSink {
    fn on_session_start(&self, manifest: &dtp_codec::TapeManifest) -> Result<(), String> {
        self.0
            .create_session(manifest.clone())
            .map_err(|e| e.to_string())
    }
    fn on_event(&self, id: &str, event: &EventEnvelope) -> Result<(), String> {
        if matches!(event.event, CoreEvent::SessionEnd { .. }) {
            return Ok(());
        }
        self.0
            .send_event(id, event.clone())
            .map_err(|e| e.to_string())
    }
    fn on_session_update(&self, manifest: &dtp_codec::TapeManifest) -> Result<(), String> {
        self.0
            .create_session(manifest.clone())
            .map_err(|e| e.to_string())
    }
}

#[tokio::main]
async fn main() -> Result<std::process::ExitCode, Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut status = std::process::ExitCode::SUCCESS;
    match cli.command {
        Commands::View { path, port } => {
            let archive = TapeArchive::decode(&fs::read(path)?)?;
            let viewer = devtape_ui::Viewer::bind(port, archive).await?;
            println!("http://{}", viewer.local_addr()?);
            viewer.serve().await?;
        }
        Commands::Mcp { tape } => {
            let archive = TapeArchive::decode(&fs::read(tape)?)?;
            devtape_mcp::serve(&archive, io::stdin().lock(), io::stdout().lock())?;
        }
        Commands::Record {
            out,
            db,
            qos,
            max_buffer_bytes,
            net,
            cmd,
        } => {
            let qos_mode = parse_qos_mode(&qos)?;
            let store = open_store(db)?;
            let proxy = if net {
                Some(devtape_net::Proxy::start().await?)
            } else {
                None
            };
            let config = RecordConfig {
                sink: Some(std::sync::Arc::new(StoreSink(store.clone()))),
                extra_env: proxy
                    .as_ref()
                    .map(|p| p.child_env_vars())
                    .unwrap_or_default(),
                command: cmd,
                interactive_stdin: std::io::IsTerminal::is_terminal(&std::io::stdin()),
                qos_mode,
                max_buffer_bytes,
                ..RecordConfig::default()
            };
            let mut outcome = PtyRecorder::record(config).await?;
            if let Some(proxy) = proxy {
                let captured = proxy.shutdown().await?;
                let mut events = outcome.archive.events;
                let mut end = events.pop().ok_or("missing session end")?;
                let root = events.first().ok_or("missing session start")?;
                let span_id = root.span_id.clone();
                let parent_span_id = root.parent_span_id.clone();
                for capture in captured.events {
                    events.push(EventEnvelope {
                        seq: 0,
                        hlc: capture.hlc,
                        span_id: span_id.clone(),
                        parent_span_id: parent_span_id.clone(),
                        event: capture.event,
                    });
                }
                // Keep lifecycle start first; order concurrent observations by their clocks.
                events[2..].sort_by_key(|e| e.hlc);
                let mut clock = events[0].hlc;
                for (index, event) in events.iter_mut().enumerate() {
                    event.seq = index as u64 + 1;
                    if index > 0 {
                        clock.merge(event.hlc, event.hlc.physical_ms);
                        event.hlc = clock;
                    }
                }
                end.seq = events.len() as u64 + 1;
                end.hlc = clock.merge(end.hlc, end.hlc.physical_ms);
                if let CoreEvent::SessionEnd { total_events, .. } = &mut end.event {
                    *total_events = end.seq;
                }
                events.push(end);
                outcome
                    .archive
                    .manifest
                    .extensions
                    .push("ext.http.v1".into());
                outcome.archive.manifest.redaction.redacted_count += captured.redacted_count;
                outcome.archive = TapeArchive::new(outcome.archive.manifest, events)?;
            }
            let cwd = std::env::current_dir()?;
            let is_repo = std::process::Command::new("git")
                .arg("-C")
                .arg(&cwd)
                .args(["rev-parse", "--show-toplevel"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if is_repo {
                match devtape_git::GitSnapshotEngine::create_snapshot(&cwd, Some("record")) {
                    Ok(mut snapshot) => {
                        let mut path_scrubber = devtape_scrub::Scrubber::new();
                        snapshot.changed_files = snapshot
                            .changed_files
                            .into_iter()
                            .map(|p| path_scrubber.scrub_str(&p))
                            .collect();
                        outcome.archive.manifest.redaction.redacted_count +=
                            path_scrubber.redacted_count();
                        let mut events = outcome.archive.events;
                        let mut end = events.pop().ok_or("missing session end")?;
                        let previous = events.last().ok_or("missing session events")?;
                        let mut clock = previous.hlc;
                        let span_id = previous.span_id.clone();
                        let parent_span_id = previous.parent_span_id.clone();
                        for event in [
                            snapshot.to_state_snapshot_event(),
                            snapshot.to_extension_event(),
                        ] {
                            let seq = events.len() as u64 + 1;
                            let wall = clock.physical_ms;
                            events.push(EventEnvelope {
                                seq,
                                hlc: clock.tick(wall),
                                span_id: span_id.clone(),
                                parent_span_id: parent_span_id.clone(),
                                event,
                            });
                        }
                        end.seq = events.len() as u64 + 1;
                        let wall = clock.physical_ms;
                        end.hlc = clock.tick(wall);
                        if let CoreEvent::SessionEnd { total_events, .. } = &mut end.event {
                            *total_events = end.seq;
                        }
                        events.push(end);
                        outcome
                            .archive
                            .manifest
                            .extensions
                            .push("ext.git.v1".into());
                        outcome.archive = TapeArchive::new(outcome.archive.manifest, events)?;
                    }
                    Err(e) => {
                        eprintln!("[devtape] warning: skipping ext.git.v1 snapshot: {e}");
                    }
                }
            }
            if let Some((payload, redacted_count)) =
                ci::github_context(|key| std::env::var(key).ok(), outcome.exit_code)
            {
                outcome.archive = ci::append_context(outcome.archive, payload, redacted_count)?;
            }
            store.store_archive(&outcome.archive)?;
            store.close()?;
            let encoded = outcome.archive.encode()?;
            fs::write(&out, &encoded)?;
            eprintln!(
                "[devtape] recorded {} events to {} ({} bytes compressed, {} secrets scrubbed, {} bytes dropped, exit_code={})",
                outcome.archive.events.len(),
                out.display(),
                encoded.len(),
                outcome.archive.manifest.redaction.redacted_count,
                outcome.bytes_dropped,
                outcome.exit_code
            );
            status = std::process::ExitCode::from(u8::try_from(outcome.exit_code).unwrap_or(1));
        }
        Commands::Ps { db, json } => {
            let path = resolve_db_path(db)?;
            let sessions = devtape_core::inspect_sessions(&path, 3_000)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&sessions)?);
            } else {
                println!("SESSION ID\tSTATUS\tELAPSED MS\tEVENTS\tCOMMAND");
                for item in sessions {
                    let status_str = match item.status {
                        devtape_core::SessionStatus::Active => "active",
                        devtape_core::SessionStatus::Stale => "stale",
                        devtape_core::SessionStatus::Completed => "completed",
                    };
                    println!(
                        "{}\t{}\t{}\t{}\t{}",
                        item.session_id,
                        status_str,
                        item.elapsed_ms,
                        item.event_count,
                        item.command
                    );
                }
            }
        }
        Commands::Tail {
            session_id,
            latest,
            follow,
            filter,
            json,
            db,
        } => {
            if session_id.is_some() && latest {
                return Err("cannot specify both <SESSION_ID> and --latest".into());
            }
            let stream_filter = devtape_core::StreamFilter::parse(&filter)?;
            let path = resolve_db_path(db)?;
            run_tail(&path, session_id.as_deref(), follow, stream_filter, json).await?;
        }
        Commands::Diff { a, b, json } => {
            let archive_a = TapeArchive::decode(&fs::read(&a)?)?;
            let archive_b = TapeArchive::decode(&fs::read(&b)?)?;
            let report = devtape_core::diff_archives(&archive_a, &archive_b);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_diff_report(&a, &b, &report);
            }
        }
        Commands::Search {
            query,
            paths,
            regex,
            stream,
            json,
            db,
        } => {
            let stream_filter = devtape_core::StreamFilter::parse(&stream)?;
            let mut matches = Vec::new();
            if paths.is_empty() {
                let store = open_store(db)?;
                let summaries = store.sessions()?;
                for s in summaries {
                    let (archive, _) = store.export_session(&s.session_id, ExportProfile::Full)?;
                    matches.extend(devtape_core::search_archive(
                        &s.session_id,
                        &archive,
                        &query,
                        regex,
                        stream_filter,
                    )?);
                }
                store.close()?;
            } else {
                for path in &paths {
                    let archive = TapeArchive::decode(&fs::read(path)?)?;
                    let source = path.display().to_string();
                    matches.extend(devtape_core::search_archive(
                        &source,
                        &archive,
                        &query,
                        regex,
                        stream_filter,
                    )?);
                }
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&matches)?);
            } else {
                for m in &matches {
                    println!(
                        "{} [{}] +{}ms [{}#{}] {}",
                        m.source, m.session_id, m.offset_ms, m.stream, m.seq, m.snippet
                    );
                }
            }
        }
        Commands::Sessions { db } => {
            let store = open_store(db)?;
            println!("{}", serde_json::to_string_pretty(&store.sessions()?)?);
            store.close()?;
        }
        Commands::Export {
            session_id,
            profile,
            format,
            review,
            db,
            out,
        } => {
            let profile = match profile.as_str() {
                "full" => ExportProfile::Full,
                "diff-only" | "diff_only" => ExportProfile::DiffOnly,
                "trace-only" | "trace_only" => ExportProfile::TraceOnly,
                _ => return Err(format!("unknown profile: {profile}").into()),
            };
            if format != "tape" && format != "html" {
                return Err(format!("unknown format: {format}").into());
            }
            let (archive, report) = if Path::new(&session_id).is_file() {
                let archive = TapeArchive::decode(&fs::read(&session_id)?)?;
                devtape_core::export_archive_with_profile(
                    archive.manifest,
                    archive.events,
                    profile,
                )?
            } else {
                let store = open_store(db)?;
                let result = store.export_session(&session_id, profile)?;
                store.close()?;
                result
            };
            if review {
                eprintln!("{}", serde_json::to_string_pretty(&report)?);
            }
            if format == "html" {
                fs::write(out, devtape_ui::render_standalone_html(archive)?)?;
            } else {
                fs::write(out, archive.encode()?)?;
            }
        }
        Commands::Snapshot { repo, label } => println!(
            "{}",
            serde_json::to_string_pretty(&devtape_git::GitSnapshotEngine::create_snapshot(
                &repo,
                label.as_deref()
            )?)?
        ),
        Commands::Rewind { repo, to } => println!(
            "{}",
            serde_json::to_string_pretty(&devtape_git::GitSnapshotEngine::rewind(
                &repo,
                to.as_deref()
            )?)?
        ),
        Commands::UndoRewind { repo } => println!(
            "{}",
            serde_json::to_string_pretty(&devtape_git::GitSnapshotEngine::undo_rewind(&repo)?)?
        ),
        Commands::DemoTape { out } => {
            let mut scrubber = OverlapScrubber::new();
            let raw_output = "Running tests with token=sk-proj-secretvalue12345678901234\n";
            let mut scrubbed = scrubber.push_chunk(raw_output);
            scrubbed.push_str(&scrubber.finish());

            let mut clock = HlcTimestamp::now(1);
            let t1 = clock.tick(clock.physical_ms);
            let t2 = clock.tick(clock.physical_ms);
            let t3 = clock.tick(clock.physical_ms);

            let manifest = TapeManifest {
                spec_version: "0.1.0".into(),
                session_id: "demo-session-001".into(),
                os: std::env::consts::OS.into(),
                arch: std::env::consts::ARCH.into(),
                shell: std::env::var("SHELL").unwrap_or_else(|_| "unknown".into()),
                qos_mode: QosMode::ZeroStall,
                export_profile: ExportProfile::Full,
                extensions: vec!["ext.git.v1".into(), "ext.mcp.v1".into()],
                redaction: RedactionAttestation {
                    ruleset_version: RULESET_VERSION.into(),
                    redacted_count: scrubber.redacted_count(),
                    local_map_excluded: true,
                },
            };

            let events = vec![
                EventEnvelope {
                    seq: 1,
                    hlc: t1,
                    span_id: "sp_0001".into(),
                    parent_span_id: None,
                    event: CoreEvent::SpanStart {
                        kind: "command".into(),
                        label: "cargo test".into(),
                    },
                },
                EventEnvelope {
                    seq: 2,
                    hlc: t2,
                    span_id: "sp_0001".into(),
                    parent_span_id: None,
                    event: CoreEvent::StreamChunk {
                        channel: StreamChannel::Stdout,
                        data: scrubbed,
                    },
                },
                EventEnvelope {
                    seq: 3,
                    hlc: t3,
                    span_id: "sp_0001".into(),
                    parent_span_id: None,
                    event: CoreEvent::SpanEnd {
                        exit_code: 0,
                        duration_ms: 42,
                    },
                },
            ];

            let archive = TapeArchive::new(manifest, events)?;
            let encoded = archive.encode()?;
            fs::write(&out, &encoded)?;
            println!(
                "Wrote DTP v0.1 archive to {} ({} bytes compressed, {} secrets scrubbed)",
                out.display(),
                encoded.len(),
                archive.manifest.redaction.redacted_count
            );
        }
        Commands::Inspect { path } => {
            let bytes = fs::read(&path)?;
            let mut archive = TapeArchive::decode(&bytes)?;
            let mut sanitizer = dtp_codec::AnsiReplaySanitizer::new();
            let mut last_chunk = None;
            for (index, envelope) in archive.events.iter_mut().enumerate() {
                match &mut envelope.event {
                    CoreEvent::StreamChunk { data, .. } => {
                        *data = sanitizer.push_chunk(data);
                        last_chunk = Some(index);
                    }
                    CoreEvent::SpanStart { label, .. } => {
                        *label = dtp_codec::sanitize_ansi_for_replay(label)
                    }
                    _ => {}
                }
            }
            if let Some(index) = last_chunk {
                if let CoreEvent::StreamChunk { data, .. } = &mut archive.events[index].event {
                    data.push_str(&sanitizer.finish());
                }
            }
            println!("{}", serde_json::to_string_pretty(&archive)?);
        }
        Commands::Doctor => {
            let git = std::process::Command::new("git")
                .arg("--version")
                .output()?;
            if !git.status.success() {
                return Err("git --version failed".into());
            }
            let pty = devtape_pty::probe_pty_support()?;
            let path = std::env::current_dir()?.join(format!(
                ".devtape-doctor-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_nanos()
            ));
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            drop(file);
            std::fs::remove_file(path)?;
            let mut scrubber = OverlapScrubber::new();
            let mut cleaned = scrubber.push_chunk("sk-proj-1234567890abcdefghijklmno");
            cleaned.push_str(&scrubber.finish());
            if !cleaned.contains("<DTP:REDACTED:API_KEY:") || scrubber.redacted_count() != 1 {
                return Err("scrubber self-check failed".into());
            }
            let manifest = TapeManifest {
                spec_version: "0.1.0".into(),
                session_id: "doctor".into(),
                os: std::env::consts::OS.into(),
                arch: std::env::consts::ARCH.into(),
                shell: "doctor".into(),
                qos_mode: QosMode::ZeroStall,
                export_profile: ExportProfile::Full,
                extensions: vec![],
                redaction: RedactionAttestation {
                    ruleset_version: RULESET_VERSION.into(),
                    redacted_count: scrubber.redacted_count(),
                    local_map_excluded: true,
                },
            };
            let archive = TapeArchive::new(manifest, vec![])?;
            if TapeArchive::decode(&archive.encode()?)? != archive {
                return Err("codec self-check failed".into());
            }
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"git": String::from_utf8_lossy(&git.stdout).trim(), "pty": pty, "term": std::env::var("TERM").ok(), "shell": std::env::var("SHELL").ok(), "cwd_write": "ok", "scrubber": RULESET_VERSION, "codec_roundtrip": "ok"})
                )?
            );
        }
        Commands::ScrubCheck => {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input)?;
            let mut scrubber = OverlapScrubber::new();
            let mut out = scrubber.push_chunk(&input);
            out.push_str(&scrubber.finish());
            print!("{out}");
            eprintln!(
                "\n[devtape-scrub] ruleset={} redacted_count={}",
                RULESET_VERSION,
                scrubber.redacted_count()
            );
        }
    }
    Ok(status)
}
