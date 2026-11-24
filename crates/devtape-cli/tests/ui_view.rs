#![forbid(unsafe_code)]
use dtp_codec::{CoreEvent, StreamChannel, TapeArchive};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Command, Stdio},
};

#[test]
fn cli_serves_sanitized_viewer() {
    let mut archive = TapeArchive::decode(include_bytes!(
        "../../../spec/conformance/03_multichannel_stdio.tape"
    ))
    .unwrap();
    let mut event = archive.events[0].clone();
    event.event = CoreEvent::StreamChunk {
        channel: StreamChannel::Stdout,
        data: "hello \x1b]52;c;secret\x07<DTP:REDACTED:BEARER:abcdef>".into(),
    };
    archive.events.push(event);
    let archive = TapeArchive::new(archive.manifest, archive.events).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let tape = tmp.path().join("test.tape");
    std::fs::write(&tape, archive.encode().unwrap()).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_devtape"))
        .arg("view")
        .arg(tape)
        .args(["--port", "0"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut address = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut address)
        .unwrap();
    let host = address.trim().strip_prefix("http://").unwrap();
    let fetch = |path: &str| {
        let mut s = TcpStream::connect(host).unwrap();
        write!(
            s,
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut result = String::new();
        s.read_to_string(&mut result).unwrap();
        result
    };
    let html = fetch("/");
    assert!(html.starts_with("HTTP/1.1 200 OK"));
    assert!(html.contains("Content-Type: text/html; charset=utf-8"));
    for term in [
        "All",
        "Failures",
        "Stdout",
        "Stdin",
        "Git",
        "HTTP",
        "DropMarkers",
        "search",
        "textContent",
    ] {
        assert!(html.contains(term));
    }
    assert!(!html.contains("innerHTML"));
    let api = fetch("/api/tape");
    assert!(api.starts_with("HTTP/1.1 200 OK"));
    assert!(api.contains("application/json"));
    assert!(!api.contains("secret"));
    assert!(!api.contains("\\u001b]52"));
    assert!(api.contains("<DTP:REDACTED:BEARER:abcdef>"));
    assert!(fetch("/missing").starts_with("HTTP/1.1 404 Not Found"));
    child.kill().unwrap();
    child.wait().unwrap();
}
