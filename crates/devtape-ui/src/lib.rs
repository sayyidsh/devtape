#![forbid(unsafe_code)]

//! Read-only, loopback-only tape viewer.
use dtp_codec::TapeArchive;
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub const HTML: &str = include_str!("../../../web/viewer/index.html");

pub struct Viewer {
    listener: TcpListener,
    json: Arc<Vec<u8>>,
}
impl Viewer {
    pub async fn bind(port: u16, mut archive: TapeArchive) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        dtp_wasm::sanitize_archive(&mut archive);
        let json = Arc::new(serde_json::to_vec(&archive)?);
        Ok(Self { listener, json })
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
    pub async fn serve(self) -> io::Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            if peer.ip().is_loopback() {
                let json = self.json.clone();
                tokio::spawn(async move {
                    let _ = respond(stream, &json).await;
                });
            }
        }
    }
}
async fn respond(mut stream: TcpStream, json: &[u8]) -> io::Result<()> {
    let mut request = vec![0u8; 8192];
    let mut used = 0;
    loop {
        let n = stream.read(&mut request[used..]).await?;
        if n == 0 {
            return Ok(());
        }
        used += n;
        if request[..used].windows(4).any(|w| w == b"\r\n\r\n") || used == request.len() {
            break;
        }
    }
    let request = String::from_utf8_lossy(&request[..used]);
    let first = request.lines().next().unwrap_or("");
    let host_ok = request
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .any(|(key, value)| {
            key.eq_ignore_ascii_case("host")
                && (value.trim() == "127.0.0.1" || value.trim().starts_with("127.0.0.1:"))
        });
    let (status, content_type, body): (&str, &str, &[u8]) = if !host_ok {
        ("400 Bad Request", "text/plain", b"Bad Request")
    } else {
        match first
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .as_slice()
        {
            ["GET", "/"] | ["GET", "/index.html"] => {
                ("200 OK", "text/html; charset=utf-8", HTML.as_bytes())
            }
            ["GET", "/api/tape"] => ("200 OK", "application/json", json),
            _ => ("404 Not Found", "text/plain", b"Not Found"),
        }
    };
    let header = format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'\r\n\r\n", body.len());
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn embedded_viewer_has_safe_filters() {
        for item in [
            "All",
            "Failures",
            "Stdout",
            "Stdin",
            "Git",
            "HTTP",
            "DropMarkers",
            "textContent",
            "search",
        ] {
            assert!(HTML.contains(item), "missing {item}");
        }
        assert!(!HTML.contains("innerHTML"));
    }
}
