//! DB-Node Message-Naht ueber UDS (Ein-Schreiber bleibt im z8run-Prozess).
//! Der Proxy ist NUR Client: serialisierte DbNodeCommand rein,
//! Vec<DbNodeEvent> raus. Kein HTTP, kein Direktzugriff auf DB-Dateien.

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::dbnode::{DbNodeCommand, DbNodeEvent};

const MAX_COMMAND: u64 = 32 * 1024 * 1024;

/// Startet den Listener; blockiert bis der Socket nicht mehr angenommen wird.
pub async fn serve(path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
    let path = path.as_ref().to_path_buf();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&path);
    let uds = tokio::net::UnixListener::bind(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    tracing::info!(path = %path.display(), "DB-Node Message-UDS bereit");
    loop {
        let (stream, _) = uds.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle(stream).await {
                tracing::warn!(error = %e, "dbnode-msg Verbindung beendet");
            }
        });
    }
}

async fn handle(stream: tokio::net::UnixStream) -> std::io::Result<()> {
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd.take(MAX_COMMAND));
    let mut line = Vec::new();
    let n = tokio::time::timeout(
        Duration::from_secs(30),
        reader.read_until(b'\n', &mut line),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "dbnode-msg Timeout"))??;
    if n == 0 {
        return Ok(());
    }
    let events = match serde_json::from_slice::<DbNodeCommand>(&line) {
        Ok(cmd) => {
            crate::nodes::dbnode_common::engine()
                .execute(cmd)
                .await
        }
        Err(e) => vec![DbNodeEvent::Error {
            db_id: String::new(),
            code: "PROTOCOL".into(),
            message: format!("Command nicht lesbar: {e}"),
        }],
    };
    let out = serde_json::to_vec(&events)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    wr.write_all(&out).await?;
    wr.write_all(b"\n").await?;
    let _ = wr.shutdown().await;
    Ok(())
}
