#![forbid(unsafe_code)]

//! Shared tape decoding and replay sanitization for viewer front ends.
use dtp_codec::{AnsiReplaySanitizer, CodecError, CoreEvent, StreamChannel, TapeArchive};
use std::collections::HashMap;

/// Sanitize stream sequences incrementally, independently for each span and channel.
/// The archive's integrity hash still identifies the original serialized archive.
pub fn sanitize_archive(archive: &mut TapeArchive) {
    let mut streams: HashMap<(String, u8), (AnsiReplaySanitizer, usize)> = HashMap::new();
    for (index, event) in archive.events.iter_mut().enumerate() {
        match &mut event.event {
            CoreEvent::SpanStart { label, .. } => {
                *label = dtp_codec::sanitize_ansi_for_replay(label)
            }
            CoreEvent::StreamChunk { channel, data } => {
                let key = (
                    event.span_id.clone(),
                    match channel {
                        StreamChannel::Stdin => 0,
                        StreamChannel::Stdout => 1,
                        StreamChannel::Stderr => 2,
                    },
                );
                let state = streams
                    .entry(key)
                    .or_insert_with(|| (AnsiReplaySanitizer::new(), index));
                *data = state.0.push_chunk(data);
                state.1 = index;
            }
            _ => {}
        }
    }
    for (_, (mut sanitizer, index)) in streams {
        if let CoreEvent::StreamChunk { data, .. } = &mut archive.events[index].event {
            data.push_str(&sanitizer.finish());
        }
    }
}

pub fn decode_and_sanitize_tape_json(bytes: &[u8]) -> Result<String, CodecError> {
    let mut archive = TapeArchive::decode(bytes)?;
    sanitize_archive(&mut archive);
    Ok(serde_json::to_string(&archive)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sanitizes_sequences_split_across_chunks() {
        let mut archive = TapeArchive::decode(include_bytes!(
            "../../../spec/conformance/03_multichannel_stdio.tape"
        ))
        .unwrap();
        let template = archive.events.first().unwrap().clone();
        archive.events.clear();
        for (i, data) in ["hello\x1b]5", "2;c;secret\x07world"].iter().enumerate() {
            let mut event = template.clone();
            event.seq = i as u64 + 1;
            event.event = CoreEvent::StreamChunk {
                channel: StreamChannel::Stdout,
                data: (*data).into(),
            };
            archive.events.push(event);
        }
        sanitize_archive(&mut archive);
        let text: String = archive
            .events
            .iter()
            .filter_map(|e| {
                if let CoreEvent::StreamChunk { data, .. } = &e.event {
                    Some(data.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(text, "helloworld");
    }
    #[test]
    fn decodes_and_sanitizes_valid_archive() {
        let value: serde_json::Value = serde_json::from_str(
            &decode_and_sanitize_tape_json(include_bytes!(
                "../../../spec/conformance/01_minimal_session.tape"
            ))
            .unwrap(),
        )
        .unwrap();
        assert!(value["manifest"]["session_id"].is_string());
        assert!(decode_and_sanitize_tape_json(b"invalid").is_err());
    }
}
