use crate::CoreError;
use dtp_codec::{CoreEvent, TapeArchive};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamFilter {
    All,
    Pty,
    Http,
    Git,
}

impl StreamFilter {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "all" => Ok(Self::All),
            "pty" => Ok(Self::Pty),
            "http" => Ok(Self::Http),
            "git" => Ok(Self::Git),
            other => Err(format!(
                "unsupported filter '{other}' (expected 'all', 'pty', 'http', or 'git')"
            )),
        }
    }

    pub fn allows_pty(self) -> bool {
        matches!(self, Self::All | Self::Pty)
    }

    pub fn allows_http(self) -> bool {
        matches!(self, Self::All | Self::Http)
    }

    pub fn allows_git(self) -> bool {
        matches!(self, Self::All | Self::Git)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventCountDelta {
    pub a: usize,
    pub b: usize,
    pub delta: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitDiffSummary {
    pub tree_blake3_a: Option<String>,
    pub tree_blake3_b: Option<String>,
    pub git_tree_oid_a: Option<String>,
    pub git_tree_oid_b: Option<String>,
    pub changed_files_a: Vec<String>,
    pub changed_files_b: Vec<String>,
    pub added_files: Vec<String>,
    pub removed_files: Vec<String>,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpExchangeDiff {
    pub method: String,
    pub url: String,
    pub status_a: Option<u16>,
    pub status_b: Option<u16>,
    pub status_changed: bool,
    pub latency_ms_a: Option<u64>,
    pub latency_ms_b: Option<u64>,
    pub latency_delta_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TapeDiffReport {
    pub session_a: String,
    pub session_b: String,
    pub exit_code_a: Option<i32>,
    pub exit_code_b: Option<i32>,
    pub exit_code_changed: bool,
    pub duration_ms_a: u64,
    pub duration_ms_b: u64,
    pub duration_delta_ms: i64,
    pub total_events_a: usize,
    pub total_events_b: usize,
    pub total_events_delta: i64,
    pub event_counts: BTreeMap<String, EventCountDelta>,
    pub git: GitDiffSummary,
    pub http: Vec<HttpExchangeDiff>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchMatch {
    pub source: String,
    pub session_id: String,
    pub seq: u64,
    pub offset_ms: u64,
    pub stream: String,
    pub snippet: String,
}

fn event_kind_key(event: &CoreEvent) -> String {
    match event {
        CoreEvent::SessionStart { .. } => "session_start".into(),
        CoreEvent::SpanStart { .. } => "span_start".into(),
        CoreEvent::StreamChunk { .. } => "stream_chunk".into(),
        CoreEvent::StateSnapshot { .. } => "state_snapshot".into(),
        CoreEvent::SpanEnd { .. } => "span_end".into(),
        CoreEvent::SessionEnd { .. } => "session_end".into(),
        CoreEvent::DropMarker { .. } => "drop_marker".into(),
        CoreEvent::Extension { extension_id, .. } => format!("extension:{extension_id}"),
    }
}

fn extract_exit_code(archive: &TapeArchive) -> Option<i32> {
    archive
        .events
        .iter()
        .rev()
        .find_map(|env| match &env.event {
            CoreEvent::SpanEnd { exit_code, .. } => Some(*exit_code),
            CoreEvent::Extension {
                extension_id,
                payload,
                ..
            } if extension_id == "ext.ci.v1" => {
                payload.get("exit_code")?.as_i64().map(|c| c as i32)
            }
            _ => None,
        })
}

fn extract_duration_ms(archive: &TapeArchive) -> u64 {
    archive
        .events
        .iter()
        .rev()
        .find_map(|env| match &env.event {
            CoreEvent::SessionEnd { duration_ms, .. } | CoreEvent::SpanEnd { duration_ms, .. } => {
                Some(*duration_ms)
            }
            _ => None,
        })
        .unwrap_or_else(|| match (archive.events.first(), archive.events.last()) {
            (Some(first), Some(last)) => last.hlc.physical_ms.saturating_sub(first.hlc.physical_ms),
            _ => 0,
        })
}

#[derive(Default)]
struct GitSnapshotInfo {
    tree_blake3: Option<String>,
    git_tree_oid: Option<String>,
    changed_files: BTreeSet<String>,
}

fn extract_git_info(archive: &TapeArchive) -> GitSnapshotInfo {
    let mut info = GitSnapshotInfo::default();
    for env in &archive.events {
        match &env.event {
            CoreEvent::StateSnapshot {
                tree_blake3,
                changed_files,
            } => {
                info.tree_blake3 = Some(tree_blake3.clone());
                for f in changed_files {
                    info.changed_files.insert(f.clone());
                }
            }
            CoreEvent::Extension {
                extension_id,
                payload,
                ..
            } if extension_id == "ext.git.v1" => {
                if let Some(oid) = payload.get("git_tree_oid").and_then(|v| v.as_str()) {
                    info.git_tree_oid = Some(oid.to_string());
                }
                if let Some(tree) = payload.get("tree_blake3").and_then(|v| v.as_str()) {
                    info.tree_blake3.get_or_insert_with(|| tree.to_string());
                }
                if let Some(arr) = payload.get("changed_files").and_then(|v| v.as_array()) {
                    for item in arr {
                        if let Some(path) = item.as_str() {
                            info.changed_files.insert(path.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    info
}

#[derive(Clone)]
struct HttpEntry {
    method: String,
    url: String,
    status: u16,
    latency_ms: u64,
}

fn extract_http_entries(archive: &TapeArchive) -> Vec<HttpEntry> {
    let mut out = Vec::new();
    for env in &archive.events {
        if let CoreEvent::Extension {
            extension_id,
            payload,
            ..
        } = &env.event
        {
            if extension_id == "ext.http.v1" {
                let method = payload
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("GET")
                    .to_string();
                let url = payload
                    .get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let status = payload.get("status").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                let latency_ms = payload
                    .get("latency_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                out.push(HttpEntry {
                    method,
                    url,
                    status,
                    latency_ms,
                });
            }
        }
    }
    out
}

/// Compare two verified DTP v0.1 archives deterministically.
pub fn diff_archives(raw_a: &TapeArchive, raw_b: &TapeArchive) -> TapeDiffReport {
    let mut a = raw_a.clone();
    let mut b = raw_b.clone();
    dtp_wasm::sanitize_archive(&mut a);
    dtp_wasm::sanitize_archive(&mut b);

    let exit_code_a = extract_exit_code(&a);
    let exit_code_b = extract_exit_code(&b);
    let duration_ms_a = extract_duration_ms(&a);
    let duration_ms_b = extract_duration_ms(&b);

    let mut counts_a: BTreeMap<String, usize> = BTreeMap::new();
    let mut counts_b: BTreeMap<String, usize> = BTreeMap::new();
    let mut all_keys: BTreeSet<String> = BTreeSet::new();

    for env in &a.events {
        let key = event_kind_key(&env.event);
        *counts_a.entry(key.clone()).or_insert(0) += 1;
        all_keys.insert(key);
    }
    for env in &b.events {
        let key = event_kind_key(&env.event);
        *counts_b.entry(key.clone()).or_insert(0) += 1;
        all_keys.insert(key);
    }

    let mut event_counts = BTreeMap::new();
    for key in all_keys {
        let ca = counts_a.get(&key).copied().unwrap_or(0);
        let cb = counts_b.get(&key).copied().unwrap_or(0);
        event_counts.insert(
            key,
            EventCountDelta {
                a: ca,
                b: cb,
                delta: cb as i64 - ca as i64,
            },
        );
    }

    let git_a = extract_git_info(&a);
    let git_b = extract_git_info(&b);
    let changed_files_a: Vec<String> = git_a.changed_files.iter().cloned().collect();
    let changed_files_b: Vec<String> = git_b.changed_files.iter().cloned().collect();
    let added_files: Vec<String> = git_b
        .changed_files
        .difference(&git_a.changed_files)
        .cloned()
        .collect();
    let removed_files: Vec<String> = git_a
        .changed_files
        .difference(&git_b.changed_files)
        .cloned()
        .collect();
    let git_changed = git_a.tree_blake3 != git_b.tree_blake3
        || git_a.git_tree_oid != git_b.git_tree_oid
        || changed_files_a != changed_files_b;

    let http_a = extract_http_entries(&a);
    let http_b = extract_http_entries(&b);
    let max_http = http_a.len().max(http_b.len());
    let mut http = Vec::with_capacity(max_http);
    for idx in 0..max_http {
        match (http_a.get(idx), http_b.get(idx)) {
            (Some(ea), Some(eb)) if ea.method == eb.method && ea.url == eb.url => {
                http.push(HttpExchangeDiff {
                    method: ea.method.clone(),
                    url: ea.url.clone(),
                    status_a: Some(ea.status),
                    status_b: Some(eb.status),
                    status_changed: ea.status != eb.status,
                    latency_ms_a: Some(ea.latency_ms),
                    latency_ms_b: Some(eb.latency_ms),
                    latency_delta_ms: Some(eb.latency_ms as i64 - ea.latency_ms as i64),
                });
            }
            (Some(ea), Some(eb)) => {
                http.push(HttpExchangeDiff {
                    method: ea.method.clone(),
                    url: ea.url.clone(),
                    status_a: Some(ea.status),
                    status_b: None,
                    status_changed: true,
                    latency_ms_a: Some(ea.latency_ms),
                    latency_ms_b: None,
                    latency_delta_ms: None,
                });
                http.push(HttpExchangeDiff {
                    method: eb.method.clone(),
                    url: eb.url.clone(),
                    status_a: None,
                    status_b: Some(eb.status),
                    status_changed: true,
                    latency_ms_a: None,
                    latency_ms_b: Some(eb.latency_ms),
                    latency_delta_ms: None,
                });
            }
            (Some(ea), None) => {
                http.push(HttpExchangeDiff {
                    method: ea.method.clone(),
                    url: ea.url.clone(),
                    status_a: Some(ea.status),
                    status_b: None,
                    status_changed: true,
                    latency_ms_a: Some(ea.latency_ms),
                    latency_ms_b: None,
                    latency_delta_ms: None,
                });
            }
            (None, Some(eb)) => {
                http.push(HttpExchangeDiff {
                    method: eb.method.clone(),
                    url: eb.url.clone(),
                    status_a: None,
                    status_b: Some(eb.status),
                    status_changed: true,
                    latency_ms_a: None,
                    latency_ms_b: Some(eb.latency_ms),
                    latency_delta_ms: None,
                });
            }
            (None, None) => {}
        }
    }

    let total_events_a = a.events.len();
    let total_events_b = b.events.len();

    TapeDiffReport {
        session_a: a.manifest.session_id,
        session_b: b.manifest.session_id,
        exit_code_a,
        exit_code_b,
        exit_code_changed: exit_code_a != exit_code_b,
        duration_ms_a,
        duration_ms_b,
        duration_delta_ms: duration_ms_b as i64 - duration_ms_a as i64,
        total_events_a,
        total_events_b,
        total_events_delta: total_events_b as i64 - total_events_a as i64,
        event_counts,
        git: GitDiffSummary {
            tree_blake3_a: git_a.tree_blake3,
            tree_blake3_b: git_b.tree_blake3,
            git_tree_oid_a: git_a.git_tree_oid,
            git_tree_oid_b: git_b.git_tree_oid,
            changed_files_a,
            changed_files_b,
            added_files,
            removed_files,
            changed: git_changed,
        },
        http,
    }
}

/// Search a verified DTP v0.1 archive for literal or regular-expression matches across PTY, HTTP, and Git streams.
pub fn search_archive(
    source: &str,
    raw_archive: &TapeArchive,
    query: &str,
    use_regex: bool,
    filter: StreamFilter,
) -> Result<Vec<SearchMatch>, CoreError> {
    let compiled_regex = if use_regex {
        Some(Regex::new(query).map_err(|e| CoreError::Actor(format!("invalid regex: {e}")))?)
    } else {
        None
    };
    let matches_query = |text: &str| -> bool {
        if let Some(ref re) = compiled_regex {
            re.is_match(text)
        } else {
            text.contains(query)
        }
    };

    let mut archive = raw_archive.clone();
    dtp_wasm::sanitize_archive(&mut archive);
    let session_id = archive.manifest.session_id.clone();
    let base_ms = archive
        .events
        .first()
        .map(|e| e.hlc.physical_ms)
        .unwrap_or(0);

    let mut results = Vec::new();
    for env in &archive.events {
        let offset_ms = env.hlc.physical_ms.saturating_sub(base_ms);
        match &env.event {
            CoreEvent::SpanStart { label, .. } if filter.allows_pty() => {
                if matches_query(label) {
                    results.push(SearchMatch {
                        source: source.to_string(),
                        session_id: session_id.clone(),
                        seq: env.seq,
                        offset_ms,
                        stream: "pty".into(),
                        snippet: label.clone(),
                    });
                }
            }
            CoreEvent::StreamChunk { data, .. } if filter.allows_pty() => {
                let mut matched_any = false;
                for raw_line in data.lines() {
                    let line = raw_line.trim_end_matches('\r');
                    if !line.is_empty() && matches_query(line) {
                        results.push(SearchMatch {
                            source: source.to_string(),
                            session_id: session_id.clone(),
                            seq: env.seq,
                            offset_ms,
                            stream: "pty".into(),
                            snippet: line.to_string(),
                        });
                        matched_any = true;
                    }
                }
                if !matched_any {
                    let trimmed = data.trim_end_matches(['\r', '\n']);
                    if !trimmed.is_empty() && matches_query(trimmed) {
                        results.push(SearchMatch {
                            source: source.to_string(),
                            session_id: session_id.clone(),
                            seq: env.seq,
                            offset_ms,
                            stream: "pty".into(),
                            snippet: trimmed.to_string(),
                        });
                    }
                }
            }
            CoreEvent::Extension {
                extension_id,
                payload,
                ..
            } if extension_id == "ext.http.v1" && filter.allows_http() => {
                let mut candidates = Vec::new();
                let method = payload.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let url = payload.get("url").and_then(|v| v.as_str()).unwrap_or("");
                let status = payload
                    .get("status")
                    .and_then(|v| v.as_u64())
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                candidates.push(format!("{method} {url} -> {status}"));
                for key in ["request_headers", "response_headers"] {
                    if let Some(arr) = payload.get(key).and_then(|v| v.as_array()) {
                        for h in arr {
                            let name = h.get("name").and_then(|v| v.as_str()).unwrap_or("");
                            let val = h.get("value").and_then(|v| v.as_str()).unwrap_or("");
                            candidates.push(format!("{name}: {val}"));
                        }
                    }
                }
                for key in ["request_body", "response_body"] {
                    if let Some(body) = payload.get(key).and_then(|v| v.as_str()) {
                        for line in body.lines() {
                            let clean = line.trim_end_matches('\r');
                            if !clean.is_empty() {
                                candidates.push(clean.to_string());
                            }
                        }
                    }
                }
                let mut seen = BTreeSet::new();
                for candidate in candidates {
                    if matches_query(&candidate) && seen.insert(candidate.clone()) {
                        results.push(SearchMatch {
                            source: source.to_string(),
                            session_id: session_id.clone(),
                            seq: env.seq,
                            offset_ms,
                            stream: "http".into(),
                            snippet: candidate,
                        });
                    }
                }
            }
            CoreEvent::StateSnapshot {
                tree_blake3,
                changed_files,
            } if filter.allows_git() => {
                let mut candidates = vec![format!("tree_blake3={tree_blake3}")];
                candidates.extend(changed_files.iter().cloned());
                for candidate in candidates {
                    if matches_query(&candidate) {
                        results.push(SearchMatch {
                            source: source.to_string(),
                            session_id: session_id.clone(),
                            seq: env.seq,
                            offset_ms,
                            stream: "git".into(),
                            snippet: candidate,
                        });
                    }
                }
            }
            CoreEvent::Extension {
                extension_id,
                payload,
                ..
            } if extension_id == "ext.git.v1" && filter.allows_git() => {
                let mut candidates = Vec::new();
                for key in [
                    "snapshot_id",
                    "git_tree_oid",
                    "tree_blake3",
                    "head_oid",
                    "branch",
                ] {
                    if let Some(val) = payload.get(key).and_then(|v| v.as_str()) {
                        candidates.push(format!("{key}={val}"));
                    }
                }
                if let Some(arr) = payload.get("changed_files").and_then(|v| v.as_array()) {
                    for item in arr {
                        if let Some(path) = item.as_str() {
                            candidates.push(path.to_string());
                        }
                    }
                }
                let mut seen = BTreeSet::new();
                for candidate in candidates {
                    if matches_query(&candidate) && seen.insert(candidate.clone()) {
                        results.push(SearchMatch {
                            source: source.to_string(),
                            session_id: session_id.clone(),
                            seq: env.seq,
                            offset_ms,
                            stream: "git".into(),
                            snippet: candidate,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    Ok(results)
}
