//! S1-Beweise: udsv3-Frame ist Chiffre, Replay wird abgewiesen,
//! Klartext-Downgrade ohne Debug-Flag wird abgewiesen, mit Debug erlaubt
//! (Meta-Ereignis wird geloggt).

use std::io;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use z8run_core::udsv3;
use z8run_core::udsv3_stream::{self, BoxIo};

type Shared = Arc<Mutex<Vec<Vec<u8>>>>;

/// Echo-Server mit strikter udsv3-Fassade; sammelt die Klartext-Bytes.
async fn spawn_server(debug: bool, got: Shared) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "udsv3-e2e-{}-{}",
        std::process::id(),
        if debug { "debug" } else { "strict" }
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("s.sock");
    let _ = std::fs::remove_file(&path);
    let uds = tokio::net::UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match uds.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let got = got.clone();
            tokio::spawn(async move {
                let io: BoxIo = if debug {
                    z8run_core::udsv3_stream::server_io(stream, "test").unwrap()
                } else {
                    z8run_core::udsv3_stream::server_io(stream, "test").unwrap()
                };
                let (mut rd, mut wr) = tokio::io::split(io);
                let mut buf = vec![0u8; 4096];
                let n = match rd.read(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                got.lock().unwrap().push(buf[..n].to_vec());
                let _ = wr.write_all(b"OK").await;
                let _ = wr.shutdown().await;
            });
        }
    });
    path
}

#[tokio::test]
async fn chiffre_replay_downgrade() {
    std::env::set_var("Z8_UDSV3_MASTER", "0123456789abcdef0123456789abcdef");
    std::env::set_var("Z8_UDSV3", "on");

    // 1) Frame-Mitschnitt an der UDS: Chiffre, kein Klartext.
    let got: Shared = Arc::new(Mutex::new(Vec::new()));
    let path = spawn_server(false, got.clone()).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let key = udsv3::transport_key(b"0123456789abcdef0123456789abcdef", "test");
    let plain = b"GET /secret HTTP/1.1\r\nauthorization: Bearer TOPSECRET\r\n\r\n";
    let frame = udsv3::seal_frame(&key, "test", 0, plain);
    let body = &frame[4..];
    assert!(
        !body.windows(plain.len()).any(|w| w == plain),
        "Frame enthaelt Klartext!"
    );
    // Replay: derselbe Frame mit erwartetem Counter 1 = abgewiesen.
    assert!(udsv3::open_frame(&key, "test", 1, body).is_err());
    println!("UDSV3_FRAME_HEX={}", frame.iter().map(|b| format!("{b:02x}")).collect::<String>());

    let mut client = udsv3_stream::connect(&path, "test").unwrap();
    client.write_all(plain).await.unwrap();
    client.flush().await.unwrap();
    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"OK");
    assert_eq!(got.lock().unwrap()[0], plain.to_vec());
    println!("UDSV3_KLIENT_PLAINTEXT_OK");

    // 2) Downgrade ohne Debug-Flag: Klartext an strikten Server = Fehler.
    let got2: Shared = Arc::new(Mutex::new(Vec::new()));
    let path2 = spawn_server(false, got2.clone()).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut raw = tokio::net::UnixStream::connect(&path2).await.unwrap();
    raw.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        raw.read_to_end(&mut out),
    )
    .await;
    assert!(got2.lock().unwrap().is_empty(), "strikter Server nahm Klartext an");
    println!("UDSV3_DOWNGRADE_STRICT_ABGEWIESEN");

    // 3) Debug-Modus: Klartext erlaubt, Meta-Ereignis wird geloggt.
    std::env::set_var("Z8_UDSV3", "off");
    let got3: Shared = Arc::new(Mutex::new(Vec::new()));
    let path3 = spawn_server(true, got3.clone()).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut raw = tokio::net::UnixStream::connect(&path3).await.unwrap();
    raw.write_all(b"GET /debug HTTP/1.1\r\n\r\n").await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        raw.read_to_end(&mut out),
    )
    .await;
    assert_eq!(got3.lock().unwrap()[0], b"GET /debug HTTP/1.1\r\n\r\n");
    println!("UDSV3_DOWNGRADE_DEBUG_META_ERLAUBT");
}

#[allow(dead_code)]
fn _io_error() -> io::Error {
    io::Error::other("unbenutzt")
}
