#![cfg(unix)]
use dtp_codec::{CoreEvent, StreamChannel, TapeArchive};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

#[test]
fn interactive_mode_forwards_live_pty_stdin_and_resize() {
    let path = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "devtape-interactive-{}-{}.tape",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_devtape"));
    command.cwd(std::env::current_dir().unwrap());
    command.args(["record", "--out", path.to_str().unwrap()]);
    command.env("SHELL", "/bin/sh");
    let mut child = pair.slave.spawn_command(command).unwrap();
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().unwrap();
    let reader_thread = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = reader.read_to_end(&mut bytes);
        bytes
    });
    let mut writer = pair.master.take_writer().unwrap();
    std::thread::sleep(Duration::from_millis(700));
    pair.master
        .resize(PtySize {
            rows: 40,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    std::thread::sleep(Duration::from_millis(700));
    if let Err(e) = writer
        .write_all(b"stty size\necho INTERACTIVE_KEY=sk-proj-1234567890abcdefghijklmno\nexit\n")
    {
        drop(writer);
        drop(pair.master);
        let out = reader_thread.join().unwrap();
        panic!(
            "write_all failed: {e:?}, child status: {:?}, output: {}",
            child.try_wait(),
            String::from_utf8_lossy(&out)
        );
    }
    writer.flush().unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("interactive recorder did not exit");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    drop(writer);
    drop(pair.master);
    let output = reader_thread.join().unwrap();
    assert!(status.success(), "{}", String::from_utf8_lossy(&output));
    let archive = TapeArchive::decode(&std::fs::read(&path).unwrap()).unwrap();
    std::fs::remove_file(path).unwrap();
    for channel in [StreamChannel::Stdin, StreamChannel::Stdout] {
        let data: String = archive
            .events
            .iter()
            .filter_map(|e| match &e.event {
                CoreEvent::StreamChunk { channel: c, data } if *c == channel => Some(data.as_str()),
                _ => None,
            })
            .collect();
        assert!(data.contains("INTERACTIVE_KEY="), "{channel:?}: {data:?}");
        assert!(
            data.contains("<DTP:REDACTED:API_KEY:"),
            "{channel:?}: {data:?}"
        );
        assert!(!data.contains("sk-proj-1234567890abcdefghijklmno"));
        if channel == StreamChannel::Stdout {
            assert!(data.contains("40 120"), "{data:?}");
        }
    }
    assert!(archive.events.iter().any(|e| matches!(&e.event, CoreEvent::Extension { event_name, payload, .. } if event_name == "terminal_resize" && payload["rows"] == 40 && payload["cols"] == 120)));
}
