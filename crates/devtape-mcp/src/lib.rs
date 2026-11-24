#![forbid(unsafe_code)]

use dtp_codec::{sanitize_ansi_for_replay, CoreEvent, StreamChannel, TapeArchive};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

/// Serve one verified archive over MCP stdio. Both line and Content-Length framing are accepted.
pub fn serve<R: BufRead, W: Write>(
    archive: &TapeArchive,
    mut input: R,
    mut output: W,
) -> io::Result<()> {
    loop {
        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            return Ok(());
        }
        if line.trim().is_empty() {
            continue;
        }
        let framed = line.to_ascii_lowercase().starts_with("content-length:");
        let bytes = if framed {
            let len: usize = line
                .split_once(':')
                .and_then(|(_, x)| x.trim().parse().ok())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid Content-Length")
                })?;
            if len > 16 * 1024 * 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "message too large",
                ));
            }
            loop {
                line.clear();
                if input.read_line(&mut line)? == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                if line.trim().is_empty() {
                    break;
                }
            }
            let mut bytes = vec![0; len];
            input.read_exact(&mut bytes)?;
            bytes
        } else {
            line.into_bytes()
        };
        let request: Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => {
                write_response(
                    &mut output,
                    &json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}),
                    framed,
                )?;
                continue;
            }
        };
        if let Some(response) = handle(archive, &request) {
            write_response(&mut output, &response, framed)?;
        }
    }
}
fn write_response<W: Write>(out: &mut W, value: &Value, framed: bool) -> io::Result<()> {
    let data = serde_json::to_vec(value)?;
    if framed {
        write!(out, "Content-Length: {}\r\n\r\n", data.len())?;
    }
    out.write_all(&data)?;
    if !framed {
        out.write_all(b"\n")?;
    }
    out.flush()
}
fn tools() -> Value {
    json!([
        {"name":"tape_summary","description":"Summarize the recorded session","inputSchema":{"type":"object","properties":{}}},
        {"name":"tape_get_failures","description":"Read failed spans and dropped data","inputSchema":{"type":"object","properties":{}}},
        {"name":"tape_get_diff","description":"Read snapshots and Git metadata","inputSchema":{"type":"object","properties":{}}},
        {"name":"tape_search_logs","description":"Search sanitized recorded streams","inputSchema":{"type":"object","properties":{"query":{"type":"string"},"channel":{"type":"string","enum":["stdin","stdout","stderr"]},"case_sensitive":{"type":"boolean"},"limit":{"type":"integer","minimum":0}},"required":["query"]}}
    ])
}
/// Dispatch a JSON-RPC request. Notifications never receive a response.
pub fn handle(archive: &TapeArchive, req: &Value) -> Option<Value> {
    let id = req.get("id")?.clone();
    let error =
        |code, message| json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}});
    if req.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Some(error(-32600, "Invalid Request"));
    }
    let result = match req.get("method").and_then(Value::as_str) {
        Some("initialize") => {
            json!({"protocolVersion": req.pointer("/params/protocolVersion").and_then(Value::as_str).unwrap_or("2024-11-05"), "capabilities":{"tools":{}},"serverInfo":{"name":"devtape-mcp","version":"0.1.0"}})
        }
        Some("tools/list") => json!({"tools":tools()}),
        Some("tools/call") => {
            let name = req
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let args = req
                .pointer("/params/arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match call(archive, name, &args) {
                Ok(data) => {
                    json!({"content":[{"type":"text","text":data.to_string()}],"isError":false})
                }
                Err(message) => return Some(error(-32602, message)),
            }
        }
        _ => return Some(error(-32601, "Method not found")),
    };
    Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
}
/// Execute a read-only tool against an already decoded archive.
pub fn call(a: &TapeArchive, name: &str, args: &Value) -> Result<Value, &'static str> {
    match name {
        "tape_summary" => {
            let mut v = serde_json::to_value(&a.manifest).map_err(|_| "invalid manifest")?;
            let m = v.as_object_mut().ok_or("invalid manifest")?;
            m.insert("total_events".into(), json!(a.events.len()));
            m.insert(
                "span_count".into(),
                json!(a
                    .events
                    .iter()
                    .filter(|e| matches!(e.event, CoreEvent::SpanStart { .. }))
                    .count()),
            );
            m.insert(
                "failed_span_count".into(),
                json!(a
                    .events
                    .iter()
                    .filter(
                        |e| matches!(e.event, CoreEvent::SpanEnd{exit_code,..} if exit_code != 0)
                    )
                    .count()),
            );
            m.insert(
                "drop_marker_count".into(),
                json!(a
                    .events
                    .iter()
                    .filter(|e| matches!(e.event, CoreEvent::DropMarker { .. }))
                    .count()),
            );
            m.insert(
                "bytes_dropped".into(),
                json!(a
                    .events
                    .iter()
                    .map(
                        |e| if let CoreEvent::DropMarker { bytes_dropped, .. } = e.event {
                            bytes_dropped
                        } else {
                            0
                        }
                    )
                    .sum::<u64>()),
            );
            m.insert(
                "snapshot_count".into(),
                json!(a
                    .events
                    .iter()
                    .filter(|e| matches!(e.event, CoreEvent::StateSnapshot { .. }))
                    .count()),
            );
            m.insert("http_event_count".into(), json!(a.events.iter().filter(|e| matches!(&e.event, CoreEvent::Extension{extension_id,..} if extension_id == "ext.http.v1")).count()));
            m.insert("integrity_blake3".into(), json!(a.integrity_blake3));
            Ok(v)
        }
        "tape_get_failures" => {
            let failures: Vec<_> = a.events.iter().filter_map(|end| {
                let CoreEvent::SpanEnd{exit_code,duration_ms} = &end.event else { return None }; if *exit_code == 0 { return None; }
                let start = a.events.iter().find(|e| e.span_id == end.span_id && matches!(e.event, CoreEvent::SpanStart{..}));
                let (kind,label) = start.and_then(|e| if let CoreEvent::SpanStart{kind,label} = &e.event {Some((kind.as_str(),label.as_str()))} else {None}).unwrap_or(("", ""));
                let stream = |wanted| a.events.iter().filter_map(|e| match &e.event { CoreEvent::StreamChunk{channel,data} if e.span_id == end.span_id && *channel == wanted => Some(data.as_str()), _ => None }).collect::<String>();
                Some(json!({"span_id":end.span_id,"parent_span_id":end.parent_span_id,"kind":kind,"label":sanitize_ansi_for_replay(label),"exit_code":exit_code,"duration_ms":duration_ms,"stdout":sanitize_ansi_for_replay(&stream(StreamChannel::Stdout)),"stderr":sanitize_ansi_for_replay(&stream(StreamChannel::Stderr))}))
            }).collect();
            let drops: Vec<_> = a
                .events
                .iter()
                .filter_map(|e| {
                    if let CoreEvent::DropMarker {
                        bytes_dropped,
                        reason,
                    } = &e.event
                    {
                        Some(json!({"bytes_dropped":bytes_dropped,"reason":reason}))
                    } else {
                        None
                    }
                })
                .collect();
            Ok(json!({"failures":failures,"drop_markers":drops}))
        }
        "tape_get_diff" => {
            let snapshots: Vec<_> = a
                .events
                .iter()
                .filter_map(|e| {
                    if let CoreEvent::StateSnapshot {
                        tree_blake3,
                        changed_files,
                    } = &e.event
                    {
                        Some(json!({"tree_blake3":tree_blake3,"changed_files":changed_files}))
                    } else {
                        None
                    }
                })
                .collect();
            let git: Vec<_> = a
                .events
                .iter()
                .filter_map(|e| {
                    if let CoreEvent::Extension {
                        extension_id,
                        event_name,
                        payload,
                    } = &e.event
                    {
                        if extension_id == "ext.git.v1" {
                            return Some(json!({"event_name":event_name,"payload":payload}));
                        }
                        None
                    } else {
                        None
                    }
                })
                .collect();
            Ok(json!({"snapshots":snapshots,"git":git}))
        }
        "tape_search_logs" => {
            let q = args
                .get("query")
                .and_then(Value::as_str)
                .ok_or("query must be a string")?;
            let channel = args
                .get("channel")
                .map(|x| x.as_str().ok_or("invalid channel"))
                .transpose()?;
            if channel.is_some_and(|x| !["stdin", "stdout", "stderr"].contains(&x)) {
                return Err("invalid channel");
            }
            let sensitive = args
                .get("case_sensitive")
                .map(|v| v.as_bool().ok_or("invalid case_sensitive"))
                .transpose()?
                .unwrap_or(false);
            let limit = args
                .get("limit")
                .map(|v| v.as_u64().ok_or("invalid limit"))
                .transpose()?
                .unwrap_or(100)
                .min(10_000) as usize;
            let needle = if sensitive {
                q.to_string()
            } else {
                q.to_lowercase()
            };
            let chunks: Vec<_> = a
                .events
                .iter()
                .filter_map(|e| {
                    if let CoreEvent::StreamChunk { channel: ch, data } = &e.event {
                        let ch = match ch {
                            StreamChannel::Stdin => "stdin",
                            StreamChannel::Stdout => "stdout",
                            StreamChannel::Stderr => "stderr",
                        };
                        let data = sanitize_ansi_for_replay(data);
                        let haystack = if sensitive {
                            data.clone()
                        } else {
                            data.to_lowercase()
                        };
                        if (channel.is_none() || channel == Some(ch)) && haystack.contains(&needle)
                        {
                            Some(json!({"seq":e.seq,"span_id":e.span_id,"channel":ch,"data":data}))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .take(limit)
                .collect();
            Ok(json!({"matches":chunks}))
        }
        _ => Err("unknown tool"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handles_framed_and_newline_requests() {
        let tape = TapeArchive::decode(include_bytes!(
            "../../../spec/conformance/01_minimal_session.tape"
        ))
        .unwrap();
        let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let framed = format!("Content-Length: {}\r\n\r\n{}", request.len(), request);
        let mut output = Vec::new();
        serve(&tape, framed.as_bytes(), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        let (_, body) = text.split_once("\r\n\r\n").unwrap();
        let result: Value = serde_json::from_str(body).unwrap();
        assert_eq!(result["id"], 1);
        assert_eq!(result["result"]["tools"].as_array().unwrap().len(), 4);
        let mut output = Vec::new();
        serve(&tape, format!("{request}\n").as_bytes(), &mut output).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&output).unwrap(), result);
    }
    #[test]
    fn notifications_are_ignored_and_queries_validated() {
        let tape = TapeArchive::decode(include_bytes!(
            "../../../spec/conformance/01_minimal_session.tape"
        ))
        .unwrap();
        assert!(handle(
            &tape,
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .is_none());
        assert!(call(
            &tape,
            "tape_search_logs",
            &json!({"query":"x","channel":"bad"})
        )
        .is_err());
        assert_eq!(
            call(&tape, "tape_summary", &json!({})).unwrap()["total_events"],
            tape.events.len()
        );
    }
}
