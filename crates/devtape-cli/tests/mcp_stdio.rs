#![forbid(unsafe_code)]
use dtp_codec::{
    CoreEvent, EventEnvelope, ExportProfile, HlcTimestamp, QosMode, RedactionAttestation,
    StreamChannel, TapeArchive, TapeManifest,
};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn mcp_stdio_serves_exact_failing_tape() {
    let osc = "\x1b]52;c;secret\x07";
    let events = vec![
        CoreEvent::SpanStart{kind:"command".into(),label:format!("build{osc}")},
        CoreEvent::StreamChunk{channel:StreamChannel::Stdout,data:format!("hello {osc}<DTP:REDACTED:BEARER:abc123>")},
        CoreEvent::StreamChunk{channel:StreamChannel::Stderr,data:format!("failure {osc}oops")},
        CoreEvent::SpanEnd{exit_code:101,duration_ms:55},
        CoreEvent::DropMarker{bytes_dropped:4096,reason:"qos0_channel_backpressure".into()},
        CoreEvent::StateSnapshot{tree_blake3:"abc123".into(),changed_files:vec!["src/lib.rs".into()]},
        CoreEvent::Extension{extension_id:"ext.git.v1".into(),event_name:"shadow_snapshot".into(),payload:json!({"snapshot_id":"snap-1","git_tree_oid":"deadbeef","head_oid":"cafebabe","branch":"main"})},
    ].into_iter().enumerate().map(|(i,event)|EventEnvelope{seq:i as u64+1,hlc:HlcTimestamp{physical_ms:100+i as u64,logical:0,node_id:1},span_id:"span-1".into(),parent_span_id:Some("parent-1".into()),event}).collect();
    let manifest = TapeManifest {
        spec_version: "0.1.0".into(),
        session_id: "session-1".into(),
        os: "test-os".into(),
        arch: "test-arch".into(),
        shell: "sh".into(),
        qos_mode: QosMode::ZeroStall,
        export_profile: ExportProfile::Full,
        extensions: vec!["ext.git.v1".into()],
        redaction: RedactionAttestation {
            ruleset_version: "test".into(),
            redacted_count: 1,
            local_map_excluded: true,
        },
    };
    let archive = TapeArchive::new(manifest, events).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("failing.tape");
    std::fs::write(&path, archive.encode().unwrap()).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_devtape"))
        .arg("mcp")
        .arg("--tape")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let requests = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"tape_summary"}}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"tape_get_failures"}}),
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"tape_get_diff"}}),
        json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"tape_search_logs","arguments":{"query":"hello","channel":"stdout"}}}),
    ];
    let mut responses = Vec::new();
    for req in requests {
        writeln!(input, "{req}").unwrap();
        input.flush().unwrap();
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        responses.push(serde_json::from_str::<Value>(&line).unwrap());
    }
    assert_eq!(
        responses[0],
        json!({"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"devtape-mcp","version":"0.1.0"}}})
    );
    let expected_tools = json!([
        {"name":"tape_summary","description":"Summarize the recorded session","inputSchema":{"type":"object","properties":{}}},
        {"name":"tape_get_failures","description":"Read failed spans and dropped data","inputSchema":{"type":"object","properties":{}}},
        {"name":"tape_get_diff","description":"Read snapshots and Git metadata","inputSchema":{"type":"object","properties":{}}},
        {"name":"tape_search_logs","description":"Search sanitized recorded streams","inputSchema":{"type":"object","properties":{"query":{"type":"string"},"channel":{"type":"string","enum":["stdin","stdout","stderr"]},"case_sensitive":{"type":"boolean"},"limit":{"type":"integer","minimum":0}},"required":["query"]}}
    ]);
    assert_eq!(
        responses[1],
        json!({"jsonrpc":"2.0","id":2,"result":{"tools":expected_tools}})
    );
    let payload = |i: usize| {
        assert_eq!(responses[i]["result"]["isError"], false);
        serde_json::from_str::<Value>(
            responses[i]["result"]["content"][0]["text"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    };
    assert_eq!(
        payload(2),
        json!({"spec_version":"0.1.0","session_id":"session-1","os":"test-os","arch":"test-arch","shell":"sh","qos_mode":"zero_stall","export_profile":"full","extensions":["ext.git.v1"],"redaction":{"ruleset_version":"test","redacted_count":1,"local_map_excluded":true},"total_events":7,"span_count":1,"failed_span_count":1,"drop_marker_count":1,"bytes_dropped":4096,"snapshot_count":1,"http_event_count":0,"integrity_blake3":archive.integrity_blake3})
    );
    assert_eq!(
        payload(3),
        json!({"failures":[{"span_id":"span-1","parent_span_id":"parent-1","kind":"command","label":"build","exit_code":101,"duration_ms":55,"stdout":"hello <DTP:REDACTED:BEARER:abc123>","stderr":"failure oops"}],"drop_markers":[{"bytes_dropped":4096,"reason":"qos0_channel_backpressure"}]})
    );
    assert_eq!(
        payload(4),
        json!({"snapshots":[{"tree_blake3":"abc123","changed_files":["src/lib.rs"]}],"git":[{"event_name":"shadow_snapshot","payload":{"snapshot_id":"snap-1","git_tree_oid":"deadbeef","head_oid":"cafebabe","branch":"main"}}]})
    );
    assert_eq!(
        payload(5),
        json!({"matches":[{"seq":2,"span_id":"span-1","channel":"stdout","data":"hello <DTP:REDACTED:BEARER:abc123>"}]})
    );
    drop(input);
    assert!(child.wait().unwrap().success());
}
