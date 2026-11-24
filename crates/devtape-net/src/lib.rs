#![forbid(unsafe_code)]

//! Opt-in loopback HTTP recording proxy. HTTPS CONNECT is explicitly rejected.
use devtape_scrub::Scrubber;
use dtp_codec::{CoreEvent, HlcTimestamp};
use serde_json::{json, Value};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinSet,
};

pub const MAX_CAPTURED_BODY_BYTES: usize = 1024 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;

pub struct Capture {
    pub hlc: HlcTimestamp,
    pub event: CoreEvent,
}
#[derive(Default)]
struct Shared {
    captures: Vec<Capture>,
    redacted_count: u64,
    clock: Option<HlcTimestamp>,
}
pub struct Proxy {
    addr: SocketAddr,
    cert: tempfile::NamedTempFile,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
    shared: Arc<Mutex<Shared>>,
}
pub struct Captures {
    pub events: Vec<Capture>,
    pub redacted_count: u64,
}
impl Proxy {
    pub async fn start() -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let key = rcgen::KeyPair::generate().map_err(io::Error::other)?;
        let mut params =
            rcgen::CertificateParams::new(Vec::<String>::new()).map_err(io::Error::other)?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let pem = params.self_signed(&key).map_err(io::Error::other)?.pem();
        let mut cert = tempfile::NamedTempFile::new()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            cert.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        std::io::Write::write_all(&mut cert, pem.as_bytes())?;
        let shared = Arc::new(Mutex::new(Shared::default()));
        let state = shared.clone();
        let (stop, mut done) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut done => break,
                    accepted = listener.accept() => match accepted { Ok((stream, _)) => { let state = state.clone(); connections.spawn(async move { let _ = exchange(stream, state).await; }); }, Err(_) => break },
                    Some(_) = connections.join_next(), if !connections.is_empty() => {},
                }
            }
            // The child has exited. Do not hang forever on abandoned connections.
            while !connections.is_empty() {
                if tokio::time::timeout(std::time::Duration::from_secs(2), connections.join_next())
                    .await
                    .is_err()
                {
                    connections.abort_all();
                    break;
                }
            }
        });
        Ok(Self {
            addr,
            cert,
            stop: Some(stop),
            task: Some(task),
            shared,
        })
    }
    pub fn child_env_vars(&self) -> Vec<(String, String)> {
        let url = format!("http://{}", self.addr);
        let pem = self.cert.path().to_string_lossy().into_owned();
        [
            ("HTTP_PROXY", &url),
            ("HTTPS_PROXY", &url),
            ("SSL_CERT_FILE", &pem),
            ("NODE_EXTRA_CA_CERTS", &pem),
            ("REQUESTS_CA_BUNDLE", &pem),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.clone()))
        .collect()
    }
    pub async fn shutdown(mut self) -> io::Result<Captures> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.await.map_err(io::Error::other)?;
        }
        let mut shared = self
            .shared
            .lock()
            .map_err(|_| io::Error::other("capture lock poisoned"))?;
        Ok(Captures {
            events: std::mem::take(&mut shared.captures),
            redacted_count: shared.redacted_count,
        })
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn read_header(stream: &mut TcpStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut data = Vec::new();
    let mut buf = [0; 8192];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        data.extend_from_slice(&buf[..n]);
        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            if pos + 4 > MAX_HEADER_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "header too large",
                ));
            }
            let body = data.split_off(pos + 4);
            return Ok((data, body));
        }
        if data.len() > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header too large",
            ));
        }
    }
}
fn capture_append(capture: &mut Vec<u8>, chunk: &[u8]) {
    let remaining = MAX_CAPTURED_BODY_BYTES.saturating_sub(capture.len());
    capture.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
}
fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
async fn exchange(mut client: TcpStream, state: Arc<Mutex<Shared>>) -> io::Result<()> {
    let start = Instant::now();
    let (header, initial) = read_header(&mut client).await?;
    let mut slots = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut slots);
    req.parse(&header).map_err(io::Error::other)?;
    let method = req
        .method
        .ok_or_else(|| io::Error::other("missing method"))?
        .to_owned();
    if method == "CONNECT" {
        client
            .write_all(
                b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .await?;
        return Ok(());
    }
    let target = req.path.ok_or_else(|| io::Error::other("missing target"))?;
    let host = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .ok_or_else(|| io::Error::other("missing Host"))?;
    let (authority, path, url) = if let Some(rest) = target.strip_prefix("http://") {
        let i = rest.find('/').unwrap_or(rest.len());
        let auth = &rest[..i];
        let path = if i == rest.len() { "/" } else { &rest[i..] };
        (auth.to_string(), path.to_string(), target.to_string())
    } else if target.starts_with('/') {
        (
            host.to_string(),
            target.to_string(),
            format!("http://{host}{target}"),
        )
    } else {
        return Err(io::Error::other("unsupported request target"));
    };
    if req
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err(io::Error::other("chunked request unsupported"));
    }
    let len: u64 = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .map(|h| {
            std::str::from_utf8(h.value)
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .ok_or_else(|| io::Error::other("invalid Content-Length"))
        })
        .transpose()?
        .unwrap_or(0);
    if initial.len() as u64 > len {
        return Err(io::Error::other("unexpected request bytes"));
    }
    let mut scrub = Scrubber::new();
    let safe_url = scrub.scrub_str(&url);
    let mut safe_req = Vec::<Value>::new();
    let mut upstream_header = format!("{method} {path} HTTP/1.1\r\n");
    for h in req.headers.iter() {
        let value = String::from_utf8_lossy(h.value);
        safe_req.push(json!({"name":h.name,"value":scrub.scrub_str(&value)}));
        if !h.name.eq_ignore_ascii_case("proxy-connection")
            && !h.name.eq_ignore_ascii_case("connection")
        {
            upstream_header.push_str(&format!("{}: {}\r\n", h.name, value));
        }
    }
    upstream_header.push_str("Connection: close\r\n\r\n");
    let destination = if authority.starts_with('[') {
        if authority.contains("]:") {
            authority.clone()
        } else {
            format!("{authority}:80")
        }
    } else if authority.contains(':') {
        authority.clone()
    } else {
        format!("{authority}:80")
    };
    let mut upstream = TcpStream::connect(destination).await?;
    upstream.write_all(upstream_header.as_bytes()).await?;
    upstream.write_all(&initial).await?;
    let mut request_body = Vec::new();
    capture_append(&mut request_body, &initial);
    let mut request_bytes = initial.len() as u64;
    let mut buf = [0u8; 16384];
    while request_bytes < len {
        let cap = ((len - request_bytes) as usize).min(buf.len());
        let n = client.read(&mut buf[..cap]).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        upstream.write_all(&buf[..n]).await?;
        capture_append(&mut request_body, &buf[..n]);
        request_bytes += n as u64;
    }
    let (response_header, first) = read_header(&mut upstream).await?;
    let mut rs = [httparse::EMPTY_HEADER; 128];
    let mut response = httparse::Response::new(&mut rs);
    response.parse(&response_header).map_err(io::Error::other)?;
    let status = response
        .code
        .ok_or_else(|| io::Error::other("missing status"))?;
    let safe_resp: Vec<_> = response
        .headers
        .iter()
        .map(|h| json!({"name":h.name,"value":scrub.scrub_str(&String::from_utf8_lossy(h.value))}))
        .collect();
    client.write_all(&response_header).await?;
    client.write_all(&first).await?;
    let mut response_body = Vec::new();
    capture_append(&mut response_body, &first);
    let mut response_bytes = first.len() as u64;
    loop {
        let n = upstream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        client.write_all(&buf[..n]).await?;
        capture_append(&mut response_body, &buf[..n]);
        response_bytes += n as u64;
    }
    // A truncated prefix can end in the middle of a secret. Discard its tail
    // before scrubbing so a partial token is not persisted at the boundary.
    if request_bytes > MAX_CAPTURED_BODY_BYTES as u64 {
        request_body.truncate(request_body.len().saturating_sub(256));
    }
    if response_bytes > MAX_CAPTURED_BODY_BYTES as u64 {
        response_body.truncate(response_body.len().saturating_sub(256));
    }
    let request_text = scrub.scrub_str(&String::from_utf8_lossy(&request_body));
    let response_text = scrub.scrub_str(&String::from_utf8_lossy(&response_body));
    let event = CoreEvent::Extension {
        extension_id: "ext.http.v1".into(),
        event_name: "http_exchange".into(),
        payload: json!({"method":method,"url":safe_url,"request_headers":safe_req,"response_headers":safe_resp,"request_body":request_text,"response_body":response_text,"request_body_truncated":request_bytes > MAX_CAPTURED_BODY_BYTES as u64,"response_body_truncated":response_bytes > MAX_CAPTURED_BODY_BYTES as u64,"status":status,"latency_ms":start.elapsed().as_millis() as u64,"request_bytes":request_bytes,"response_bytes":response_bytes,"bytes":request_bytes + response_bytes}),
    };
    let mut shared = state
        .lock()
        .map_err(|_| io::Error::other("capture lock poisoned"))?;
    shared.redacted_count += scrub.redacted_count();
    let clock = shared.clock.get_or_insert_with(|| HlcTimestamp::now(10));
    let hlc = clock.tick(wall_ms());
    shared.captures.push(Capture { hlc, event });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn captures_large_body_and_scrubs_headers() {
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (mut socket, _) = server.accept().await.unwrap();
            let (_, initial) = read_header(&mut socket).await.unwrap();
            let mut count = initial.len();
            let mut buf = [0; 16384];
            while count < MAX_CAPTURED_BODY_BYTES + 17 {
                let n = socket.read(&mut buf).await.unwrap();
                assert_ne!(n, 0);
                count += n;
            }
            let body = vec![b'x'; MAX_CAPTURED_BODY_BYTES + 23];
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            socket.write_all(&body).await.unwrap();
        });
        let proxy = Proxy::start().await.unwrap();
        let pem = proxy.cert.path().to_path_buf();
        assert!(pem.exists());
        let mut client = TcpStream::connect(proxy.addr).await.unwrap();
        let body = vec![b'a'; MAX_CAPTURED_BODY_BYTES + 17];
        client.write_all(format!("POST http://{addr}/test HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer supersecret_token_1234567890\r\nContent-Length: {}\r\n\r\n",body.len()).as_bytes()).await.unwrap();
        client.write_all(&body).await.unwrap();
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert!(received.ends_with(&vec![b'x'; MAX_CAPTURED_BODY_BYTES + 23]));
        server_task.await.unwrap();
        let captures = proxy.shutdown().await.unwrap();
        assert!(!pem.exists());
        assert_eq!(captures.redacted_count, 1);
        let CoreEvent::Extension { payload, .. } = &captures.events[0].event else {
            panic!("missing event")
        };
        assert_eq!(payload["request_body_truncated"], true);
        assert_eq!(payload["response_body_truncated"], true);
        assert_eq!(payload["request_bytes"], MAX_CAPTURED_BODY_BYTES + 17);
        assert_eq!(payload["response_bytes"], MAX_CAPTURED_BODY_BYTES + 23);
        let data = payload.to_string();
        assert!(!data.contains("supersecret_token_1234567890"));
        assert!(data.contains("<DTP:REDACTED:BEARER:"));
    }
    #[tokio::test]
    async fn origin_form_is_forwarded() {
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = server.accept().await.unwrap();
            let (head, _) = read_header(&mut stream).await.unwrap();
            assert!(head.starts_with(b"GET /hello HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        let proxy = Proxy::start().await.unwrap();
        let mut client = TcpStream::connect(proxy.addr).await.unwrap();
        client
            .write_all(format!("GET /hello HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        task.await.unwrap();
        let result = proxy.shutdown().await.unwrap();
        assert_eq!(result.events.len(), 1);
    }
}
