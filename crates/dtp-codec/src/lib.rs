#![forbid(unsafe_code)]

//! Core DTP v0.1 codec: Hybrid Logical Clocks, Event Envelopes, and `.tape` container I/O.

use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const TAPE_MAGIC: &[u8; 6] = b"DTAP01";
pub const TAPE_FORMAT_VERSION: u16 = 1;
pub const MAX_DECOMPRESSION_RATIO: usize = 100;
pub const DEFAULT_MAX_UNCOMPRESSED_BYTES: usize = 256 * 1024 * 1024; // 256 MiB

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("invalid .tape magic header")]
    InvalidMagic,
    #[error("unsupported .tape format version: {0}")]
    UnsupportedVersion(u16),
    #[error("decompression bomb detected: declared {declared} bytes exceeds limit {limit}")]
    DecompressionLimitExceeded { declared: usize, limit: usize },
    #[error("unsafe path detected in snapshot: {0}")]
    UnsafePath(String),
    #[error("exported tape cannot contain an attached local redaction map")]
    LocalMapNotExcluded,
    #[error("integrity hash mismatch")]
    IntegrityMismatch,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Hybrid Logical Clock guaranteeing monotonic causal ordering across concurrent producers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HlcTimestamp {
    pub physical_ms: u64,
    pub logical: u32,
    pub node_id: u32,
}

impl HlcTimestamp {
    pub fn now(node_id: u32) -> Self {
        let physical_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            physical_ms,
            logical: 0,
            node_id,
        }
    }

    /// Advances the local clock monotonically against a new wall-clock reading.
    pub fn tick(&mut self, wall_ms: u64) -> Self {
        if wall_ms > self.physical_ms {
            self.physical_ms = wall_ms;
            self.logical = 0;
        } else {
            self.logical = self.logical.saturating_add(1);
        }
        *self
    }

    /// Merges a remote producer's HLC timestamp to preserve causal ordering.
    pub fn merge(&mut self, remote: HlcTimestamp, wall_ms: u64) -> Self {
        let max_phys = self.physical_ms.max(remote.physical_ms).max(wall_ms);
        if max_phys == self.physical_ms && max_phys == remote.physical_ms {
            self.logical = self.logical.max(remote.logical).saturating_add(1);
        } else if max_phys == self.physical_ms {
            self.logical = self.logical.saturating_add(1);
        } else if max_phys == remote.physical_ms {
            self.physical_ms = remote.physical_ms;
            self.logical = remote.logical.saturating_add(1);
        } else {
            self.physical_ms = max_phys;
            self.logical = 0;
        }
        *self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QosMode {
    ZeroStall,
    Lossless,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportProfile {
    Full,
    DiffOnly,
    TraceOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamChannel {
    Stdin,
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionAttestation {
    pub ruleset_version: String,
    pub redacted_count: u64,
    pub local_map_excluded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TapeManifest {
    pub spec_version: String,
    pub session_id: String,
    pub os: String,
    pub arch: String,
    pub shell: String,
    pub qos_mode: QosMode,
    pub export_profile: ExportProfile,
    pub extensions: Vec<String>,
    pub redaction: RedactionAttestation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoreEvent {
    SessionStart {
        sanitized_cwd: String,
        env_fingerprint: String,
    },
    SpanStart {
        kind: String,
        label: String,
    },
    SpanEnd {
        exit_code: i32,
        duration_ms: u64,
    },
    StreamChunk {
        channel: StreamChannel,
        data: String,
    },
    StateSnapshot {
        tree_blake3: String,
        changed_files: Vec<String>,
    },
    DropMarker {
        bytes_dropped: u64,
        reason: String,
    },
    SessionEnd {
        total_events: u64,
        duration_ms: u64,
    },
    /// Forward-compatible extension event preserved verbatim by older readers.
    Extension {
        extension_id: String,
        event_name: String,
        payload: serde_json::Value,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub seq: u64,
    pub hlc: HlcTimestamp,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub event: CoreEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TapeArchive {
    pub manifest: TapeManifest,
    pub events: Vec<EventEnvelope>,
    pub integrity_blake3: String,
}

/// Stateful filter for clipboard and window-title OSC commands.
#[derive(Default)]
pub struct AnsiReplaySanitizer {
    prefix: String,
    suppressing: bool,
    escape_in_payload: bool,
}

impl AnsiReplaySanitizer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_chunk(&mut self, chunk: &str) -> String {
        const HEADERS: [&str; 4] = ["\x1b]52;", "\x1b]0;", "\x1b]1;", "\x1b]2;"];
        let mut out = String::new();
        for c in chunk.chars() {
            if self.suppressing {
                if c == '\x07' || (self.escape_in_payload && c == '\\') {
                    self.suppressing = false;
                    self.escape_in_payload = false;
                } else {
                    self.escape_in_payload = c == '\x1b';
                }
                continue;
            }
            self.prefix.push(c);
            loop {
                if HEADERS.contains(&self.prefix.as_str()) {
                    self.prefix.clear();
                    self.suppressing = true;
                    break;
                }
                if HEADERS.iter().any(|h| h.starts_with(&self.prefix)) {
                    break;
                }
                let first = self.prefix.chars().next().unwrap();
                out.push(first);
                self.prefix.drain(..first.len_utf8());
                if self.prefix.is_empty() {
                    break;
                }
            }
        }
        out
    }

    /// Flushes an incomplete harmless prefix; an incomplete targeted OSC is discarded.
    pub fn finish(&mut self) -> String {
        self.suppressing = false;
        self.escape_in_payload = false;
        std::mem::take(&mut self.prefix)
    }
}

/// Removes clipboard and window-title OSC commands from terminal replay.
pub fn sanitize_ansi_for_replay(input: &str) -> String {
    let mut sanitizer = AnsiReplaySanitizer::new();
    let mut output = sanitizer.push_chunk(input);
    output.push_str(&sanitizer.finish());
    output
}

/// Validates that a relative path inside a snapshot cannot escape the repository root.
pub fn validate_safe_relative_path(path: &str) -> Result<(), CodecError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\0')
        || path.contains("..")
        || (path.len() >= 2 && path.as_bytes()[1] == b':')
    {
        return Err(CodecError::UnsafePath(path.to_string()));
    }
    Ok(())
}

impl TapeArchive {
    pub fn new(manifest: TapeManifest, events: Vec<EventEnvelope>) -> Result<Self, CodecError> {
        if !manifest.redaction.local_map_excluded {
            return Err(CodecError::LocalMapNotExcluded);
        }
        for env in &events {
            if let CoreEvent::StateSnapshot { changed_files, .. } = &env.event {
                for f in changed_files {
                    validate_safe_relative_path(f)?;
                }
            }
        }
        let body_bytes = serde_json::to_vec(&(&manifest, &events))?;
        let integrity_blake3 = blake3::hash(&body_bytes).to_hex().to_string();
        Ok(Self {
            manifest,
            events,
            integrity_blake3,
        })
    }

    /// Encodes the archive into the `DTAP01` binary container with Zstd compression.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if !self.manifest.redaction.local_map_excluded {
            return Err(CodecError::LocalMapNotExcluded);
        }
        let json = serde_json::to_vec(self)?;
        let compressed = zstd::stream::encode_all(Cursor::new(&json), 3)?;

        let mut out = Vec::with_capacity(16 + compressed.len());
        out.extend_from_slice(TAPE_MAGIC);
        out.extend_from_slice(&TAPE_FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(&(json.len() as u64).to_be_bytes());
        out.extend_from_slice(&compressed);
        Ok(out)
    }

    /// Decodes a `DTAP01` binary container while enforcing decompression-bomb and path-safety rules.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        Self::decode_with_limit(bytes, DEFAULT_MAX_UNCOMPRESSED_BYTES)
    }

    pub fn decode_with_limit(bytes: &[u8], max_uncompressed: usize) -> Result<Self, CodecError> {
        if bytes.len() < 16 || &bytes[0..6] != TAPE_MAGIC {
            return Err(CodecError::InvalidMagic);
        }
        let version = u16::from_be_bytes([bytes[6], bytes[7]]);
        if version != TAPE_FORMAT_VERSION {
            return Err(CodecError::UnsupportedVersion(version));
        }
        // Check before converting to usize: a malicious u64 header must not wrap
        // on wasm32 (or other 32-bit targets) and bypass the size guard.
        let declared_len = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        let compressed = &bytes[16..];

        let ratio_limit = compressed
            .len()
            .saturating_mul(MAX_DECOMPRESSION_RATIO)
            .max(4096);
        let hard_limit = max_uncompressed.min(ratio_limit);

        if declared_len > hard_limit as u64 {
            return Err(CodecError::DecompressionLimitExceeded {
                declared: usize::try_from(declared_len).unwrap_or(usize::MAX),
                limit: hard_limit,
            });
        }

        let decoder = zstd::stream::read::Decoder::new(Cursor::new(compressed))?;
        let mut limited = decoder.take((hard_limit + 1) as u64);
        let mut raw = Vec::new();
        limited.read_to_end(&mut raw)?;

        if raw.len() > hard_limit {
            return Err(CodecError::DecompressionLimitExceeded {
                declared: raw.len(),
                limit: hard_limit,
            });
        }

        let archive: TapeArchive = serde_json::from_slice(&raw)?;
        if !archive.manifest.redaction.local_map_excluded {
            return Err(CodecError::LocalMapNotExcluded);
        }
        for env in &archive.events {
            if let CoreEvent::StateSnapshot { changed_files, .. } = &env.event {
                for f in changed_files {
                    validate_safe_relative_path(f)?;
                }
            }
        }
        let recomputed = blake3::hash(&serde_json::to_vec(&(&archive.manifest, &archive.events))?)
            .to_hex()
            .to_string();
        if recomputed != archive.integrity_blake3 {
            return Err(CodecError::IntegrityMismatch);
        }
        Ok(archive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> TapeManifest {
        TapeManifest {
            spec_version: "0.1.0".into(),
            session_id: "sess_01".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            shell: "zsh".into(),
            qos_mode: QosMode::ZeroStall,
            export_profile: ExportProfile::Full,
            extensions: vec!["ext.git.v1".into(), "ext.mcp.v1".into()],
            redaction: RedactionAttestation {
                ruleset_version: "dtp-scrub-0.1".into(),
                redacted_count: 1,
                local_map_excluded: true,
            },
        }
    }

    #[test]
    fn replay_sanitizer_removes_targeted_osc_and_preserves_sgr() {
        let input = "é\x1b[31mred\x1b[0m\x1b]52;c;secret\x07A\x1b]0;title\x1b\\B\x1b]1;title\x07C\x1b]2;title\x1b\\D\x1b]52;unfinished";
        assert_eq!(sanitize_ansi_for_replay(input), "é\x1b[31mred\x1b[0mABCD");
    }

    #[test]
    fn replay_sanitizer_handles_split_sequences() {
        let mut s = AnsiReplaySanitizer::new();
        let mut out = String::new();
        for part in [
            "é\x1b[31m",
            "红\x1b",
            "]5",
            "2;payload\x1b",
            "\\",
            "\x1b[0m",
        ] {
            out.push_str(&s.push_chunk(part));
        }
        out.push_str(&s.finish());
        assert_eq!(out, "é\x1b[31m红\x1b[0m");
    }

    #[test]
    fn hlc_preserves_monotonic_causality() {
        let mut local = HlcTimestamp {
            physical_ms: 1000,
            logical: 0,
            node_id: 1,
        };
        let t1 = local.tick(1000);
        assert_eq!(t1.logical, 1);

        let remote = HlcTimestamp {
            physical_ms: 1005,
            logical: 3,
            node_id: 2,
        };
        let t2 = local.merge(remote, 1002);
        assert_eq!(t2.physical_ms, 1005);
        assert_eq!(t2.logical, 4);
        assert!(t2 > remote);
    }

    #[test]
    fn roundtrip_tape_and_unknown_extension_preservation() {
        let hlc = HlcTimestamp {
            physical_ms: 1_760_000_000_000,
            logical: 0,
            node_id: 1,
        };
        let events = vec![
            EventEnvelope {
                seq: 1,
                hlc,
                span_id: "sp_0001".into(),
                parent_span_id: None,
                event: CoreEvent::SpanStart {
                    kind: "command".into(),
                    label: "cargo test".into(),
                },
            },
            EventEnvelope {
                seq: 2,
                hlc,
                span_id: "sp_0002".into(),
                parent_span_id: Some("sp_0001".into()),
                event: CoreEvent::Extension {
                    extension_id: "ext.future.v9".into(),
                    event_name: "custom_signal".into(),
                    payload: serde_json::json!({"ok": true}),
                },
            },
        ];

        let archive = TapeArchive::new(sample_manifest(), events).unwrap();
        let encoded = archive.encode().unwrap();
        let decoded = TapeArchive::decode(&encoded).unwrap();
        assert_eq!(archive, decoded);
    }

    #[test]
    fn rejects_path_traversal_in_snapshot() {
        let hlc = HlcTimestamp::now(1);
        let events = vec![EventEnvelope {
            seq: 1,
            hlc,
            span_id: "sp_01".into(),
            parent_span_id: None,
            event: CoreEvent::StateSnapshot {
                tree_blake3: "deadbeef".into(),
                changed_files: vec!["../../etc/passwd".into()],
            },
        }];
        let err = TapeArchive::new(sample_manifest(), events).unwrap_err();
        assert!(matches!(err, CodecError::UnsafePath(_)));
    }
}
