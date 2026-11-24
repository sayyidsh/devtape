#![forbid(unsafe_code)]

use devtape_scrub::Scrubber;
use dtp_codec::{CodecError, CoreEvent, EventEnvelope, TapeArchive};
use serde_json::{json, Value};

/// Capture only the documented allowlist; never copy the runner's entire environment.
pub fn github_context(
    mut env: impl FnMut(&str) -> Option<String>,
    exit_code: i32,
) -> Option<(Value, u64)> {
    let enabled = env("GITHUB_ACTIONS")?;
    if matches!(
        enabled.trim().to_ascii_lowercase().as_str(),
        "" | "false" | "0" | "no" | "off"
    ) {
        return None;
    }
    let mut scrubber = Scrubber::new();
    let mut value = |key| scrubber.scrub_str(&env(key).unwrap_or_default());
    let payload = json!({
        "provider": "github_actions",
        "github_actions": value("GITHUB_ACTIONS"),
        "repository": value("GITHUB_REPOSITORY"),
        "run_id": value("GITHUB_RUN_ID"),
        "sha": value("GITHUB_SHA"),
        "ref_name": value("GITHUB_REF_NAME"),
        "runner_os": value("RUNNER_OS"),
        "exit_code": exit_code,
    });
    Some((payload, scrubber.redacted_count()))
}

pub fn append_context(
    archive: TapeArchive,
    payload: Value,
    redacted_count: u64,
) -> Result<TapeArchive, CodecError> {
    let mut events = archive.events;
    let Some(mut end) = events.pop() else {
        return Err(std::io::Error::other("missing SessionEnd").into());
    };
    if !matches!(end.event, CoreEvent::SessionEnd { .. }) {
        return Err(std::io::Error::other("missing SessionEnd").into());
    }
    let mut clock = end.hlc;
    if let Some(previous) = events.last() {
        clock.merge(previous.hlc, end.hlc.physical_ms);
    }
    events.push(EventEnvelope {
        seq: 0,
        hlc: clock.tick(clock.physical_ms),
        span_id: end.span_id.clone(),
        parent_span_id: end.parent_span_id.clone(),
        event: CoreEvent::Extension {
            extension_id: "ext.ci.v1".into(),
            event_name: "ci_context".into(),
            payload,
        },
    });
    end.hlc = clock.tick(clock.physical_ms);
    events.push(end);
    let count = events.len() as u64;
    for (index, event) in events.iter_mut().enumerate() {
        event.seq = index as u64 + 1;
        if let CoreEvent::SessionEnd { total_events, .. } = &mut event.event {
            *total_events = count;
        }
    }
    let mut manifest = archive.manifest;
    if !manifest.extensions.iter().any(|id| id == "ext.ci.v1") {
        manifest.extensions.push("ext.ci.v1".into());
    }
    manifest.redaction.redacted_count = manifest
        .redaction
        .redacted_count
        .saturating_add(redacted_count);
    TapeArchive::new(manifest, events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_truthy_github_flag_without_mutating_environment() {
        for flag in ["true", "TRUE", "1", "yes"] {
            let (value, count) = github_context(
                |key| match key {
                    "GITHUB_ACTIONS" => Some(flag.into()),
                    "GITHUB_REF_NAME" => {
                        Some("secret-branch-sk-proj-1234567890abcdefghijklmno".into())
                    }
                    _ => None,
                },
                101,
            )
            .unwrap();
            assert_eq!(value["exit_code"], 101);
            assert_eq!(value["repository"], "");
            assert!(value["ref_name"]
                .as_str()
                .unwrap()
                .contains("<DTP:REDACTED:API_KEY:"));
            assert_eq!(count, 1);
        }
        for flag in [None, Some(""), Some("false"), Some("0"), Some("off")] {
            assert!(github_context(
                |key| if key == "GITHUB_ACTIONS" {
                    flag.map(str::to_string)
                } else {
                    Some("present".into())
                },
                0
            )
            .is_none());
        }
    }
}
