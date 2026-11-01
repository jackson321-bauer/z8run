//! AsyncRead/AsyncWrite-Fassade fuer udsv3 auf einem Unix-Domain-Socket.
//! Jede `poll_write`-Einheit wird EIN Frame; die Gegenseite setzt ihn
//! wieder zu Bytes zusammen. Damit laeuft auch HTTP/1.1 (hyper) durch die
//! verschluesselte Fassade, ohne dass der HTTP-Code davon weiss.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::udsv3::{self, Mode, HEADER, MAX_FRAME};

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncReadWrite for T {}
pub type BoxIo = Box<dyn AsyncReadWrite + Unpin + Send>;

pub struct Udsv3Stream<S> {
    inner: S,
    key: [u8; 32],
    context: String,
    read_counter: u64,
    inbuf: Vec<u8>,
    want: Option<usize>,
    plain: Vec<u8>,
    plain_pos: usize,
    write_counter: u64,
    out: Vec<u8>,
    out_pos: usize,
    accepted: Option<usize>,
    eof: bool,
}

impl<S> Udsv3Stream<S> {
    pub fn new(inner: S, key: [u8; 32], context: impl Into<String>) -> Self {
        Self {
            inner,
            key,
            context: context.into(),
            read_counter: 0,
            inbuf: Vec::new(),
            want: None,
            plain: Vec::new(),
            plain_pos: 0,
            write_counter: 0,
            out: Vec::new(),
            out_pos: 0,
            accepted: None,
            eof: false,
        }
    }
}

/// Klient-Seite: Key aus Env/Key-Datei, Kontext = Socket-Rolle.
pub fn connect(path: &std::path::Path, context: &str) -> io::Result<Udsv3Stream<tokio::net::UnixStream>> {
    let master = udsv3::master_from_env()?;
    let key = udsv3::transport_key(&master, context);
    let stream = std::os::unix::net::UnixStream::connect(path)?;
    stream.set_nonblocking(true)?;
    let stream = tokio::net::UnixStream::from_std(stream)?;
    Ok(Udsv3Stream::new(stream, key, context))
}

/// Server-Seite: strikt = udsv3; Debug = Klartext + Meta-Ereignis.
pub fn server_io(stream: tokio::net::UnixStream, context: &str) -> io::Result<BoxIo> {
    match Mode::from_env() {
        Mode::Strict => {
            let master = udsv3::master_from_env()?;
            let key = udsv3::transport_key(&master, context);
            Ok(Box::new(Udsv3Stream::new(stream, key, context)))
        }
        Mode::DebugPlain => {
            udsv3::meta_downgrade(context);
            Ok(Box::new(stream))
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Udsv3Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if me.plain_pos < me.plain.len() {
                let n = (me.plain.len() - me.plain_pos).min(buf.remaining());
                buf.put_slice(&me.plain[me.plain_pos..me.plain_pos + n]);
                me.plain_pos += n;
                if me.plain_pos == me.plain.len() {
                    me.plain.clear();
                    me.plain_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if let Some(total) = me.want {
                if me.inbuf.len() >= total {
                    let body: Vec<u8> = me.inbuf.drain(..total).collect();
                    me.want = None;
                    let plain = udsv3::open_frame(&me.key, &me.context, me.read_counter, &body)?;
                    me.read_counter += 1;
                    me.plain = plain;
                    me.plain_pos = 0;
                    continue;
                }
            } else if me.inbuf.len() >= 4 {
                let total = u32::from_be_bytes(me.inbuf[0..4].try_into().unwrap()) as usize;
                if total < HEADER || total > MAX_FRAME + 12 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "udsv3: Frame-Laenge ungueltig (Klartext-Downgrade?)",
                    )));
                }
                me.inbuf.drain(..4);
                me.want = Some(total);
                continue;
            }
            match me.fill(cx)? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(false) => {
                    me.eof = true;
                    if me.inbuf.is_empty() && me.want.is_none() {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "udsv3: Verbindung endet mitten im Frame",
                    )));
                }
                Poll::Ready(true) => {}
            }
        }
    }
}

impl<S: AsyncRead + Unpin> Udsv3Stream<S> {
    /// Liest mehr Bytes; `Ok(false)` = EOF.
    fn fill(&mut self, cx: &mut Context<'_>) -> io::Result<Poll<bool>> {
        let mut tmp = [0u8; 16384];
        let mut rb = ReadBuf::new(&mut tmp);
        match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
            Poll::Pending => Ok(Poll::Pending),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                if n == 0 {
                    Ok(Poll::Ready(false))
                } else {
                    self.inbuf.extend_from_slice(rb.filled());
                    Ok(Poll::Ready(true))
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Udsv3Stream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        // Ein zuvor angenommener Write wird erst als fertig gemeldet, wenn
        // seine Frames wirklich am Transport sind (Poll-Pending-Kontrakt).
        if let Some(n) = me.accepted {
            match me.flush_out(cx)? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => {
                    me.accepted = None;
                    return Poll::Ready(Ok(n));
                }
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let frame = udsv3::seal_frame(&me.key, &me.context, me.write_counter, buf);
        me.write_counter += 1;
        me.out.extend_from_slice(&frame);
        me.accepted = Some(buf.len());
        match me.flush_out(cx)? {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => {
                me.accepted = None;
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match me.flush_out(cx)? {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => {
                me.accepted = None;
                Pin::new(&mut me.inner).poll_flush(cx)
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match me.flush_out(cx)? {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => {
                me.accepted = None;
                Pin::new(&mut me.inner).poll_shutdown(cx)
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> Udsv3Stream<S> {
    fn flush_out(&mut self, cx: &mut Context<'_>) -> io::Result<Poll<()>> {
        while self.out_pos < self.out.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]) {
                Poll::Pending => return Ok(Poll::Pending),
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Ready(Ok(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "udsv3: Transport nahm keine Bytes",
                    ))
                }
                Poll::Ready(Ok(n)) => self.out_pos += n,
            }
        }
        self.out.clear();
        self.out_pos = 0;
        Ok(Poll::Ready(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn http_bytes_roundtrip_ueber_verschluesselte_fassade() {
        let (a, b) = tokio::net::UnixStream::pair().unwrap();
        let key = udsv3::transport_key(b"0123456789abcdef0123456789abcdef", "test");
        let mut client = Udsv3Stream::new(a, key, "test");
        let mut server = Udsv3Stream::new(b, key, "test");
        let req = b"POST /v1/x HTTP/1.1\r\nhost: localhost\r\ncontent-length: 5\r\n\r\nhello";
        client.write_all(req).await.unwrap();
        client.flush().await.unwrap();
        let mut got = vec![0u8; req.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, req);
        server.write_all(b"HTTP/1.1 200 OK\r\n\r\nok").await.unwrap();
        server.shutdown().await.unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        assert_eq!(&resp, b"HTTP/1.1 200 OK\r\n\r\nok");
    }

    #[tokio::test]
    async fn klartext_wird_von_strikter_fassade_abgewiesen() {
        let (a, b) = tokio::net::UnixStream::pair().unwrap();
        let key = udsv3::transport_key(b"0123456789abcdef0123456789abcdef", "test");
        let mut client = a;
        let mut server = Udsv3Stream::new(b, key, "test");
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        client.shutdown().await.unwrap();
        let mut buf = Vec::new();
        let err = server.read_to_end(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}

#[cfg(test)]
mod tests2 {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn write_ohne_flush_wird_zugestellt() {
        let (a, b) = tokio::net::UnixStream::pair().unwrap();
        let key = udsv3::transport_key(b"0123456789abcdef0123456789abcdef", "test");
        let mut client = Udsv3Stream::new(a, key, "test");
        let mut server = Udsv3Stream::new(b, key, "test");
        let req = b"POST /login HTTP/1.1\r\nhost: x\r\ncontent-length: 2\r\n\r\n{}";
        client.write_all(req).await.unwrap();
        let mut got = vec![0u8; req.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, req);
    }
}
