#![forbid(unsafe_code)]

//! Streaming secret scrubber with sliding-window overlap and deterministic structural redaction.

use regex::Regex;

pub const RULESET_VERSION: &str = "dtp-scrub-0.1";
const DEFAULT_OVERLAP_BYTES: usize = 128;

struct Rule {
    kind: &'static str,
    regex: Regex,
}

pub struct Scrubber {
    rules: Vec<Rule>,
    redacted_count: u64,
}

impl Default for Scrubber {
    fn default() -> Self {
        Self::new()
    }
}

impl Scrubber {
    pub fn new() -> Self {
        let defs: &[(&str, &str)] = &[
            ("AWS_KEY", r"\bAKIA[0-9A-Z]{16}\b"),
            (
                "GITHUB_TOKEN",
                r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b",
            ),
            ("API_KEY", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"),
            ("BEARER", r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b"),
            (
                "JWT",
                r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
            ),
        ];

        let rules = defs
            .iter()
            .map(|(kind, pat)| Rule {
                kind,
                regex: Regex::new(pat).expect("valid built-in scrubber regex"),
            })
            .collect();

        Self {
            rules,
            redacted_count: 0,
        }
    }

    pub fn redacted_count(&self) -> u64 {
        self.redacted_count
    }

    /// Scrubs a full string, replacing matched secrets with deterministic structural tokens.
    pub fn scrub_str(&mut self, input: &str) -> String {
        let mut current = input.to_string();
        for rule in &self.rules {
            let mut count = 0u64;
            current = rule
                .regex
                .replace_all(&current, |caps: &regex::Captures| {
                    count += 1;
                    let matched = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                    let digest = blake3::hash(matched.as_bytes()).to_hex();
                    let short = &digest[..6];
                    format!("<DTP:REDACTED:{}:{}>", rule.kind, short)
                })
                .into_owned();
            self.redacted_count += count;
        }
        current
    }
}

/// Sliding-window wrapper ensuring secrets split across adjacent PTY chunks are still caught.
pub struct OverlapScrubber {
    inner: Scrubber,
    tail: String,
    overlap_bytes: usize,
}

impl Default for OverlapScrubber {
    fn default() -> Self {
        Self::new()
    }
}

impl OverlapScrubber {
    pub fn new() -> Self {
        Self {
            inner: Scrubber::new(),
            tail: String::new(),
            overlap_bytes: DEFAULT_OVERLAP_BYTES,
        }
    }

    pub fn redacted_count(&self) -> u64 {
        self.inner.redacted_count()
    }

    /// Pushes a streaming chunk and returns the safe-to-emit scrubbed prefix.
    pub fn push_chunk(&mut self, chunk: &str) -> String {
        self.tail.push_str(chunk);
        if self.tail.len() <= self.overlap_bytes {
            return String::new();
        }
        let mut split_at = self.tail.len() - self.overlap_bytes;
        while !self.tail.is_char_boundary(split_at) {
            split_at -= 1;
        }
        // Never cut through a currently visible match; retain it until complete.
        for rule in &self.inner.rules {
            for matched in rule.regex.find_iter(&self.tail) {
                if matched.start() < split_at && matched.end() >= split_at {
                    split_at = matched.start();
                }
            }
        }
        // Retain the preceding token as well, preserving regex word boundaries and
        // multiword prefixes such as "Bearer ", bounded to 4x overlap_bytes so a
        // delimiter-free stream (e.g. minified JS or base64) cannot grow `tail` unboundedly.
        let min_split = split_at.saturating_sub(self.overlap_bytes * 4);
        while split_at > min_split {
            let c = self.tail[..split_at].chars().next_back().unwrap();
            split_at -= c.len_utf8();
            if c.is_whitespace() {
                break;
            }
        }
        while split_at > min_split {
            let c = self.tail[..split_at].chars().next_back().unwrap();
            if c.is_whitespace() {
                break;
            }
            split_at -= c.len_utf8();
        }
        let remainder = self.tail.split_off(split_at);
        let prefix = std::mem::replace(&mut self.tail, remainder);
        self.inner.scrub_str(&prefix)
    }

    /// Flushes any remaining buffered bytes at session end.
    pub fn finish(&mut self) -> String {
        let rest = std::mem::take(&mut self.tail);
        self.inner.scrub_str(&rest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_secret_split_across_chunks() {
        let mut s = OverlapScrubber::new();
        let mut out = String::new();
        out.push_str(&s.push_chunk("export KEY=sk-proj-123456"));
        out.push_str(&s.push_chunk("7890abcdefghijklmno\n"));
        out.push_str(&s.finish());

        assert!(!out.contains("sk-proj-123456"));
        assert!(out.contains("<DTP:REDACTED:API_KEY:"));
        assert_eq!(s.redacted_count(), 1);
    }

    #[test]
    fn preserves_normal_code_without_false_positives() {
        let mut s = Scrubber::new();
        let line = "fn main() { println!(\"hello devtape\"); }";
        assert_eq!(s.scrub_str(line), line);
        assert_eq!(s.redacted_count(), 0);
    }
}
