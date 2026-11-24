#![forbid(unsafe_code)]

//! Opt-in loopback HTTP and HTTPS recording proxy.
use devtape_scrub::Scrubber;
use dtp_codec::{CoreEvent, HlcTimestamp};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
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
struct Shared {
    ca_cert: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
    roots: rustls::RootCertStore,
    leaves: HashMap<String, Arc<rustls::ServerConfig>>,
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
        let ca_cert = params.self_signed(&key).map_err(io::Error::other)?;
        let pem = ca_cert.pem();
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        roots.add(ca_cert.der().clone()).map_err(io::Error::other)?;
        let mut cert = tempfile::NamedTempFile::new()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            cert.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        std::io::Write::write_all(&mut cert, pem.as_bytes())?;
        let shared = Arc::new(Mutex::new(Shared {
            ca_cert,
            ca_key: key,
            roots,
            leaves: HashMap::new(),
            captures: Vec::new(),
            redacted_count: 0,
            clock: None,
        }));
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
    pub fn trust_upstream_ca_der(
        &self,
        cert: rustls::pki_types::CertificateDer<'static>,
    ) -> io::Result<()> {
        self.shared
            .lock()
            .map_err(|_| io::Error::other("capture lock poisoned"))?
            .roots
            .add(cert)
            .map_err(io::Error::other)
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

async fn read_header<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<(Vec<u8>, Vec<u8>)> {
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
async fn chunk_line<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let byte = reader.read_u8().await?;
        line.push(byte);
        if line.len() > MAX_HEADER_BYTES {
            return Err(io::Error::other("chunk line too large"));
        }
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
    }
}
async fn forward_chunks<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    upstream: &mut W,
    capture: &mut Vec<u8>,
) -> io::Result<u64> {
    let mut total = 0u64;
    let mut buf = [0u8; 16384];
    loop {
        let line = chunk_line(reader).await?;
        let raw = std::str::from_utf8(&line[..line.len() - 2]).map_err(io::Error::other)?;
        let size = raw.split(';').next().unwrap_or("");
        if size.is_empty() || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(io::Error::other("invalid chunk size"));
        }
        let mut remaining = u64::from_str_radix(size, 16).map_err(io::Error::other)?;
        upstream.write_all(&line).await?;
        if remaining == 0 {
            let mut trailer_bytes = 0;
            loop {
                let trailer = chunk_line(reader).await?;
                trailer_bytes += trailer.len();
                if trailer_bytes > MAX_HEADER_BYTES {
                    return Err(io::Error::other("trailers too large"));
                }
                upstream.write_all(&trailer).await?;
                if trailer == b"\r\n" {
                    return Ok(total);
                }
            }
        }
        total = total
            .checked_add(remaining)
            .ok_or_else(|| io::Error::other("body too large"))?;
        while remaining > 0 {
            let cap = remaining.min(buf.len() as u64) as usize;
            let n = reader.read(&mut buf[..cap]).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            upstream.write_all(&buf[..n]).await?;
            capture_append(capture, &buf[..n]);
            remaining -= n as u64;
        }
        let mut ending = [0; 2];
        reader.read_exact(&mut ending).await?;
        if ending != *b"\r\n" {
            return Err(io::Error::other("invalid chunk terminator"));
        }
        upstream.write_all(&ending).await?;
    }
}
fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn destination(authority: &str, default_port: u16) -> io::Result<(String, String)> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest
            .split_once(']')
            .ok_or_else(|| io::Error::other("invalid IPv6 authority"))?;
        let port = if suffix.is_empty() {
            default_port
        } else {
            suffix
                .strip_prefix(':')
                .ok_or_else(|| io::Error::other("invalid authority"))?
                .parse()
                .map_err(io::Error::other)?
        };
        (host.to_string(), port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            return Err(io::Error::other("IPv6 authority must be bracketed"));
        }
        (host.to_string(), port.parse().map_err(io::Error::other)?)
    } else {
        (authority.to_string(), default_port)
    };
    if host.is_empty() {
        return Err(io::Error::other("empty host"));
    }
    let destination = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Ok((host, destination))
}

async fn exchange(mut client: TcpStream, state: Arc<Mutex<Shared>>) -> io::Result<()> {
    let start = Instant::now();
    let (header, initial) = read_header(&mut client).await?;
    let mut slots = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut slots);
    req.parse(&header).map_err(io::Error::other)?;
    let target = req.path.ok_or_else(|| io::Error::other("missing target"))?;
    if req.method == Some("CONNECT") {
        if !initial.is_empty() {
            return Err(io::Error::other("unexpected bytes before CONNECT response"));
        }
        let authority = target.to_string();
        let (host, dest) = destination(&authority, 443)?;
        let (roots, config) = {
            let mut shared = state
                .lock()
                .map_err(|_| io::Error::other("capture lock poisoned"))?;
            let config = if let Some(config) = shared.leaves.get(&host) {
                config.clone()
            } else {
                let mut params =
                    rcgen::CertificateParams::new(vec![host.clone()]).map_err(io::Error::other)?;
                params.is_ca = rcgen::IsCa::NoCa;
                params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
                params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
                let key = rcgen::KeyPair::generate().map_err(io::Error::other)?;
                let cert = params
                    .signed_by(&key, &shared.ca_cert, &shared.ca_key)
                    .map_err(io::Error::other)?;
                let private_key = rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der());
                let config = Arc::new(
                    rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(vec![cert.der().clone()], private_key.into())
                        .map_err(io::Error::other)?,
                );
                shared.leaves.insert(host.clone(), config.clone());
                config
            };
            (shared.roots.clone(), config)
        };
        let tcp = TcpStream::connect(dest).await?;
        let upstream_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(host).map_err(io::Error::other)?;
        let upstream = tokio_rustls::TlsConnector::from(Arc::new(upstream_config))
            .connect(name, tcp)
            .await?;
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        let mut client = tokio_rustls::TlsAcceptor::from(config)
            .accept(client)
            .await?;
        let (header, initial) = read_header(&mut client).await?;
        return capture_exchange(
            client,
            upstream,
            header,
            initial,
            state,
            Some(authority),
            start,
        )
        .await;
    }
    let host = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .ok_or_else(|| io::Error::other("missing Host"))?;
    let authority = target
        .strip_prefix("http://")
        .map(|rest| rest.split('/').next().unwrap_or(rest))
        .unwrap_or(host);
    let (_, dest) = destination(authority, 80)?;
    let upstream = TcpStream::connect(dest).await?;
    capture_exchange(client, upstream, header, initial, state, None, start).await
}

async fn capture_exchange<C: AsyncRead + AsyncWrite + Unpin, U: AsyncRead + AsyncWrite + Unpin>(
    mut client: C,
    mut upstream: U,
    header: Vec<u8>,
    initial: Vec<u8>,
    state: Arc<Mutex<Shared>>,
    connect_authority: Option<String>,
    start: Instant,
) -> io::Result<()> {
    let mut slots = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut slots);
    req.parse(&header).map_err(io::Error::other)?;
    let method = req
        .method
        .ok_or_else(|| io::Error::other("missing method"))?
        .to_owned();
    let target = req.path.ok_or_else(|| io::Error::other("missing target"))?;
    let host = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .ok_or_else(|| io::Error::other("missing Host"))?;
    let (path, url) = if let Some(authority) = connect_authority {
        if !target.starts_with('/') {
            return Err(io::Error::other("unsupported HTTPS request target"));
        }
        (target.to_string(), format!("https://{authority}{target}"))
    } else if let Some(rest) = target.strip_prefix("http://") {
        let i = rest.find('/').unwrap_or(rest.len());
        (
            if i == rest.len() { "/" } else { &rest[i..] }.to_string(),
            target.to_string(),
        )
    } else if target.starts_with('/') {
        (target.to_string(), format!("http://{host}{target}"))
    } else {
        return Err(io::Error::other("unsupported request target"));
    };
    let transfer: Vec<_> = req
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
        .collect();
    let lengths: Vec<_> = req
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
        .collect();
    if lengths.len() > 1 || (!transfer.is_empty() && !lengths.is_empty()) || transfer.len() > 1 {
        return Err(io::Error::other("ambiguous request framing"));
    }
    let chunked = if let Some(h) = transfer.first() {
        let value = std::str::from_utf8(h.value).map_err(io::Error::other)?;
        if !value.trim().eq_ignore_ascii_case("chunked") {
            return Err(io::Error::other("unsupported transfer encoding"));
        }
        true
    } else {
        false
    };
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
    if !chunked && initial.len() as u64 > len {
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
    upstream.write_all(upstream_header.as_bytes()).await?;
    let mut request_body = Vec::new();
    let mut buf = [0u8; 16384];
    let request_bytes = if chunked {
        let mut reader = initial.as_slice().chain(&mut client);
        forward_chunks(&mut reader, &mut upstream, &mut request_body).await?
    } else {
        upstream.write_all(&initial).await?;
        capture_append(&mut request_body, &initial);
        let mut count = initial.len() as u64;
        while count < len {
            let cap = ((len - count) as usize).min(buf.len());
            let n = client.read(&mut buf[..cap]).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            upstream.write_all(&buf[..n]).await?;
            capture_append(&mut request_body, &buf[..n]);
            count += n as u64;
        }
        count
    };
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
    client.shutdown().await?;
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
    async fn https_connect_terminates_tls_and_scrubs_bearer_and_chunked_body() {
        let proxy = Proxy::start().await.unwrap();
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = server.local_addr().unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
        let cert = {
            let shared = proxy.shared.lock().unwrap();
            params
                .signed_by(&key, &shared.ca_cert, &shared.ca_key)
                .unwrap()
        };
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        let expected = b"10\r\nsk-proj-12345678\r\nb\r\n90abcdefghi\r\n0\r\n\r\n";
        let server_task = tokio::spawn(async move {
            let (socket, _) = server.accept().await.unwrap();
            let mut socket = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                .accept(socket)
                .await
                .unwrap();
            let (header, mut body) = read_header(&mut socket).await.unwrap();
            assert!(header.starts_with(b"POST /secure HTTP/1.1\r\n"));
            assert!(String::from_utf8_lossy(&header).contains("supersecret_https_token_1234567890"));
            while body.len() < expected.len() {
                let mut buf = [0; 128];
                let n = socket.read(&mut buf).await.unwrap();
                assert_ne!(n, 0);
                body.extend_from_slice(&buf[..n]);
            }
            assert_eq!(body, expected);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .await
                .unwrap();
            socket.shutdown().await.unwrap();
        });
        let env: HashMap<_, _> = proxy.child_env_vars().into_iter().collect();
        let file = std::fs::File::open(&env["SSL_CERT_FILE"]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(file)) {
            roots.add(cert.unwrap()).unwrap();
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut socket = TcpStream::connect(env["HTTPS_PROXY"].strip_prefix("http://").unwrap())
            .await
            .unwrap();
        socket
            .write_all(format!("CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let (header, extra) = read_header(&mut socket).await.unwrap();
        assert!(header.starts_with(b"HTTP/1.1 200 Connection Established\r\n"));
        assert!(extra.is_empty());
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string()).unwrap();
        let mut socket = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, socket)
            .await
            .unwrap();
        socket.write_all(format!("POST /secure HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer supersecret_https_token_1234567890\r\nTransfer-Encoding: chunked\r\n\r\n").as_bytes()).await.unwrap();
        socket.write_all(expected).await.unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(response.ends_with(b"OK"));
        server_task.await.unwrap();
        let captures = proxy.shutdown().await.unwrap();
        let CoreEvent::Extension {
            extension_id,
            payload,
            ..
        } = &captures.events[0].event
        else {
            panic!("missing event")
        };
        assert_eq!(extension_id, "ext.http.v1");
        assert_eq!(payload["url"], format!("https://{addr}/secure"));
        assert_eq!(payload["status"], 200);
        assert!(payload["latency_ms"].is_number());
        let captured = payload.to_string();
        assert!(captured.contains("<DTP:REDACTED:BEARER:"));
        assert!(!captured.contains("supersecret_https_token_1234567890"));
        assert!(!captured.contains("sk-proj-1234567890abcdefghi"));
        assert!(payload["request_body"]
            .as_str()
            .unwrap()
            .contains("<DTP:REDACTED:"));
    }
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
    async fn decodes_chunk_payload_across_frames() {
        let wire = b"10;foo=bar\r\nsk-proj-12345678\r\nb\r\n90abcdefghi\r\n0\r\nX-End: yes\r\n\r\n";
        let mut input = wire.as_slice();
        let mut output = Vec::new();
        let mut capture = Vec::new();
        let count = forward_chunks(&mut input, &mut output, &mut capture)
            .await
            .unwrap();
        assert_eq!(output, wire);
        assert_eq!(count, 27);
        let mut scrubber = Scrubber::new();
        let clean = scrubber.scrub_str(std::str::from_utf8(&capture).unwrap());
        assert!(clean.contains("<DTP:REDACTED:"));
        assert!(!clean.contains("sk-proj-1234567890abcdefghi"));
    }
    #[tokio::test]
    async fn forwards_chunked_body_and_scrubs_split_secret() {
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = server.local_addr().unwrap();
        let expected =
            b"10;foo=bar\r\nsk-proj-12345678\r\nb\r\n90abcdefghi\r\n0\r\nX-End: yes\r\n\r\n";
        let task = tokio::spawn(async move {
            let (mut stream, _) = server.accept().await.unwrap();
            let (_, mut body) = read_header(&mut stream).await.unwrap();
            while body.len() < expected.len() {
                let mut buf = [0; 128];
                let n = stream.read(&mut buf).await.unwrap();
                assert_ne!(n, 0);
                body.extend_from_slice(&buf[..n]);
            }
            assert_eq!(body, expected);
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        let proxy = Proxy::start().await.unwrap();
        let mut client = TcpStream::connect(proxy.addr).await.unwrap();
        client.write_all(format!("POST http://{addr}/chunk HTTP/1.1\r\nHost: {addr}\r\nTransfer-Encoding: chunked\r\n\r\n").as_bytes()).await.unwrap();
        client.write_all(expected).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        task.await.unwrap();
        let captures = proxy.shutdown().await.unwrap();
        let CoreEvent::Extension { payload, .. } = &captures.events[0].event else {
            panic!("missing event")
        };
        assert!(!payload.to_string().contains("sk-proj-1234567890abcdefghi"));
        assert!(payload["request_body"]
            .as_str()
            .unwrap()
            .contains("<DTP:REDACTED:"));
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
