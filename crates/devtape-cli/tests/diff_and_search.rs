use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::process::Command;

fn read_http_request(stream: &mut std::net::TcpStream) {
    let mut buf = [0u8; 4096];
    let mut data = Vec::new();
    loop {
        let n = stream.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        if data.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
}

fn send_http_via_proxy(proxy_url: &str, target_addr: std::net::SocketAddr, path: &str) {
    let proxy_host = proxy_url.strip_prefix("http://").unwrap_or(proxy_url);
    let mut stream = std::net::TcpStream::connect(proxy_host).unwrap();
    write!(
        stream,
        "GET http://{target_addr}{path} HTTP/1.1\r\nHost: {target_addr}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut resp = Vec::new();
    let _ = stream.read_to_end(&mut resp);
}

#[test]
fn diff_and_search_compare_tapes_and_reject_corrupted_vectors() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("diff_search.db");
    let tape_a = dir.path().join("a.tape");
    let tape_b = dir.path().join("b.tape");

    // Start a real loopback HTTP server that serves 200 OK on first request and 503 on second.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let server_addr = listener.local_addr().unwrap();
    let server_thread = std::thread::spawn(move || {
        for (status_line, body) in [
            ("200 OK", "status=healthy_alpha"),
            ("503 Service Unavailable", "status=degraded_beta"),
        ] {
            let (mut socket, _) = listener.accept().unwrap();
            read_http_request(&mut socket);
            write!(
                socket,
                "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });

    // Helper: record a real session that connects through $HTTP_PROXY to `server_addr`.
    let record_session = |out_tape: &std::path::Path, msg: &str, exit_code: i32| {
        let cmd = if cfg!(windows) {
            vec![
                "powershell".to_string(),
                "-NoLogo".to_string(),
                "-NoProfile".to_string(),
                "-Command".to_string(),
                format!(
                    "Write-Output '{msg}'; Invoke-WebRequest -Uri 'http://{server_addr}/api/health' -Proxy $env:HTTP_PROXY -SkipHttpErrorCheck | Out-Null; exit {exit_code}"
                ),
            ]
        } else {
            vec![
                "sh".to_string(),
                "-c".to_string(),
                format!(
                    "echo '{msg}' && curl --noproxy '' -sS -x \"$HTTP_PROXY\" -o /dev/null http://{server_addr}/api/health && exit {exit_code}"
                ),
            ]
        };

        let mut args = vec![
            "record".to_string(),
            "--net".to_string(),
            "--db".to_string(),
            db.to_str().unwrap().to_string(),
            "--out".to_string(),
            out_tape.to_str().unwrap().to_string(),
            "--".to_string(),
        ];
        args.extend(cmd);

        Command::new(env!("CARGO_BIN_EXE_devtape"))
            .current_dir(dir.path())
            .args(&args)
            .output()
            .unwrap()
    };

    let out_a = record_session(&tape_a, "BUILD_ALPHA_PASS_100", 0);
    assert!(
        out_a.status.success(),
        "session A failed: {}",
        String::from_utf8_lossy(&out_a.stderr)
    );

    let out_b = record_session(&tape_b, "BUILD_BETA_FAIL_503", 7);
    assert_eq!(out_b.status.code(), Some(7));

    server_thread.join().unwrap();

    // 1. Verify `devtape diff` human output and `--json` output.
    let diff_text = Command::new(env!("CARGO_BIN_EXE_devtape"))
        .current_dir(dir.path())
        .args(["diff", tape_a.to_str().unwrap(), tape_b.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(diff_text.status.success());
    let diff_stdout = String::from_utf8_lossy(&diff_text.stdout);
    assert!(diff_stdout.contains("Exit Code: Some(0) -> Some(7) (changed: true)"));
    assert!(diff_stdout.contains("status Some(200) -> Some(503) (changed: true)"));

    let diff_json_out = Command::new(env!("CARGO_BIN_EXE_devtape"))
        .current_dir(dir.path())
        .args([
            "diff",
            tape_a.to_str().unwrap(),
            tape_b.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(diff_json_out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&diff_json_out.stdout).unwrap();
    assert_eq!(report["exit_code_a"], 0);
    assert_eq!(report["exit_code_b"], 7);
    assert_eq!(report["exit_code_changed"], true);
    assert!(report["duration_delta_ms"].is_i64());
    assert_eq!(report["http"][0]["status_a"], 200);
    assert_eq!(report["http"][0]["status_b"], 503);
    assert_eq!(report["http"][0]["status_changed"], true);

    // 2. Verify `devtape search` literal, `--regex`, `--stream`, and `--json`.
    let search_literal = Command::new(env!("CARGO_BIN_EXE_devtape"))
        .current_dir(dir.path())
        .args([
            "search",
            "BUILD_BETA_FAIL_503",
            tape_a.to_str().unwrap(),
            tape_b.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(search_literal.status.success());
    let lit_matches: serde_json::Value = serde_json::from_slice(&search_literal.stdout).unwrap();
    let lit_arr = lit_matches.as_array().unwrap();
    assert!(!lit_arr.is_empty());
    assert!(lit_arr.iter().all(|m| m["stream"] == "pty"));

    let search_http_regex = Command::new(env!("CARGO_BIN_EXE_devtape"))
        .current_dir(dir.path())
        .args([
            "search",
            "degraded_beta|503",
            tape_a.to_str().unwrap(),
            tape_b.to_str().unwrap(),
            "--regex",
            "--stream",
            "http",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(search_http_regex.status.success());
    let http_matches: serde_json::Value =
        serde_json::from_slice(&search_http_regex.stdout).unwrap();
    let http_arr = http_matches.as_array().unwrap();
    assert!(!http_arr.is_empty());
    assert!(http_arr.iter().all(|m| m["stream"] == "http"));

    // 3. Verify `devtape search` with no file paths searches the local SQLite SessionStore.
    let search_store = Command::new(env!("CARGO_BIN_EXE_devtape"))
        .current_dir(dir.path())
        .args([
            "search",
            "BUILD_ALPHA_PASS_100",
            "--db",
            db.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(search_store.status.success());
    let store_matches: serde_json::Value = serde_json::from_slice(&search_store.stdout).unwrap();
    assert!(!store_matches.as_array().unwrap().is_empty());

    // 4. Verify `devtape search` rejects a corrupted/malicious conformance vector.
    let tampered_vector = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/conformance/16_tampered_integrity_blake3.tape");
    let bad_search = Command::new(env!("CARGO_BIN_EXE_devtape"))
        .current_dir(dir.path())
        .args(["search", "hello", tampered_vector.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !bad_search.status.success(),
        "expected devtape search to reject tampered .tape conformance vector"
    );
    let _ = send_http_via_proxy;
}
