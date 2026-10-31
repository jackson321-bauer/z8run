//! Ringpuffer fuer chunked/SSE-Durchreichung (PA4): konstanter RAM-Bedarf,
//! Reihenfolge bleibt erhalten.

use crate::error::ProxyError;
use crate::traits::{ByteSink, ByteSource};

pub struct RingBuffer {
    buf: std::collections::VecDeque<u8>,
    cap: usize,
}

impl RingBuffer {
    pub fn new(cap: usize) -> Self {
        assert!(cap > 0, "Ringpuffer braucht Platz");
        Self {
            buf: std::collections::VecDeque::with_capacity(cap.min(64 * 1024)),
            cap,
        }
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn free(&self) -> usize {
        self.cap - self.buf.len()
    }

    pub fn push(&mut self, data: &[u8]) -> Result<(), ProxyError> {
        if data.len() > self.free() {
            return Err(ProxyError::Stream(format!(
                "Ringpuffer voll ({} > {})",
                data.len(),
                self.free()
            )));
        }
        self.buf.extend(data.iter().copied());
        Ok(())
    }

    pub fn pop(&mut self, max: usize) -> Option<Vec<u8>> {
        if self.buf.is_empty() {
            return None;
        }
        let n = max.min(self.buf.len());
        Some(self.buf.drain(..n).collect())
    }
}

/// Reicht eine Quelle durch eine Senke, ohne mehr als `cap` Bytes zu puffern.
/// Liefert die Gesamtzahl durchgereichter Bytes.
pub fn pump(
    source: &mut dyn ByteSource,
    sink: &mut dyn ByteSink,
    cap: usize,
) -> Result<u64, ProxyError> {
    let mut ring = RingBuffer::new(cap);
    let mut total = 0u64;
    loop {
        match source.next_chunk()? {
            None => break,
            Some(chunk) => {
                let mut rest = chunk.as_slice();
                while !rest.is_empty() {
                    if ring.free() == 0 {
                        if let Some(out) = ring.pop(ring.capacity()) {
                            total += out.len() as u64;
                            sink.write_chunk(&out)?;
                        }
                        continue;
                    }
                    let n = ring.free().min(rest.len());
                    ring.push(&rest[..n])?;
                    rest = &rest[n..];
                }
                while let Some(out) = ring.pop(ring.capacity()) {
                    total += out.len() as u64;
                    sink.write_chunk(&out)?;
                }
            }
        }
    }
    while let Some(out) = ring.pop(ring.capacity()) {
        total += out.len() as u64;
        sink.write_chunk(&out)?;
    }
    sink.finish()?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Source {
        chunks: Vec<Vec<u8>>,
        i: usize,
    }
    impl ByteSource for Source {
        fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ProxyError> {
            if self.i >= self.chunks.len() {
                return Ok(None);
            }
            let c = self.chunks[self.i].clone();
            self.i += 1;
            Ok(Some(c))
        }
    }

    struct Sink {
        received: Vec<u8>,
        writes: Vec<usize>,
    }
    impl ByteSink for Sink {
        fn write_chunk(&mut self, data: &[u8]) -> Result<(), ProxyError> {
            self.writes.push(data.len());
            self.received.extend_from_slice(data);
            Ok(())
        }
        fn finish(&mut self) -> Result<(), ProxyError> {
            Ok(())
        }
    }

    #[test]
    fn ring_haelt_grenze_und_reihenfolge() {
        let mut ring = RingBuffer::new(8);
        ring.push(b"abcdefgh").unwrap();
        assert!(ring.push(b"i").is_err());
        assert_eq!(ring.pop(3).unwrap(), b"abc".to_vec());
        ring.push(b"ijk").unwrap();
        let rest: Vec<u8> = std::iter::from_fn(|| ring.pop(8))
            .flatten()
            .collect();
        assert_eq!(rest, b"defghijk".to_vec());
    }

    #[test]
    fn pump_reicht_12_chunks_geordnet_durch() {
        let chunks: Vec<Vec<u8>> = (0..12u16)
            .map(|i| {
                let mut v = vec![i as u8; (i as usize % 5 + 1) * 7];
                v.push(0xAA);
                v
            })
            .collect();
        let expected: Vec<u8> = chunks.iter().flatten().copied().collect();
        let mut src = Source {
            chunks: chunks.clone(),
            i: 0,
        };
        let mut sink = Sink {
            received: Vec::new(),
            writes: Vec::new(),
        };
        let total = pump(&mut src, &mut sink, 23).unwrap();
        assert_eq!(total, expected.len() as u64);
        assert_eq!(sink.received, expected);
        assert!(sink.writes.iter().all(|n| *n <= 23));
    }
}
