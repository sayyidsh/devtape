#![forbid(unsafe_code)]
#[cfg(unix)]
#[test]
fn record_net_captures_scrubbed_http_exchange() {
    use dtp_codec::{CoreEvent, TapeArchive};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        process::Command,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0; 4096];
        let mut request = Vec::new();
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut buf).unwrap();
            assert_ne!(n, 0);
            request.extend_from_slice(&buf[..n]);
        }
        assert!(String::from_utf8_lossy(&request).contains("supersecret_token_1234567890"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });
    let tmp = tempfile::tempdir().unwrap();
    let tape = tmp.path().join("net.tape");
    let db = tmp.path().join("sessions.db");
    let script=format!("curl --noproxy '' -sS -x \"$HTTP_PROXY\" -H 'Authorization: Bearer supersecret_token_1234567890' http://{addr}/path");
    let output = Command::new(env!("CARGO_BIN_EXE_devtape"))
        .current_dir(tmp.path())
        .args(["record", "--net", "--out"])
        .arg(&tape)
        .arg("--db")
        .arg(db)
        .args(["--", "sh", "-c", &script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
    let archive = TapeArchive::decode(&std::fs::read(tape).unwrap()).unwrap();
    assert!(archive
        .manifest
        .extensions
        .contains(&"ext.http.v1".to_string()));
    assert!(archive.manifest.redaction.redacted_count >= 1);
    let payload = archive
        .events
        .iter()
        .find_map(|e| match &e.event {
            CoreEvent::Extension {
                extension_id,
                payload,
                ..
            } if extension_id == "ext.http.v1" => Some(payload),
            _ => None,
        })
        .unwrap();
    assert_eq!(payload["status"], 200);
    assert!(payload["latency_ms"].as_u64().is_some());
    assert_eq!(payload["bytes"], 2);
    assert!(payload.to_string().contains("<DTP:REDACTED:BEARER:"));
    assert!(!serde_json::to_string(&archive)
        .unwrap()
        .contains("supersecret_token_1234567890"));
}
