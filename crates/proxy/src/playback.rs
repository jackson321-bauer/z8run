//! Blob-Wiedergabe laeuft ueber das Kanal-Modell (G16): 12 Chunks werden
//! als normale Medien-Frames publiziert. Die alten SSE/chunked-Endpunkte
//! sind geloescht (404), es gibt keine Geradeaus-Durchreichung mehr.

use proxy_kern::ProxyError;

use crate::channel::ChannelRegistry;
use crate::frame::TYP_MEDIA;

pub const CHUNKS: usize = 12;
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// Determinierter Chunk i: 1-basierter 4-Byte-LE-Index + Fuellbytes.
pub fn blob_chunk(i: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(CHUNK_SIZE);
    v.extend_from_slice(&((i + 1) as u32).to_le_bytes());
    v.extend(std::iter::repeat_n(((i as u8).wrapping_add(1)) | 0x80, CHUNK_SIZE - 4));
    v
}

pub fn blob_total() -> u64 {
    (CHUNKS * CHUNK_SIZE) as u64
}

pub fn blob_sha_hex() -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for i in 0..CHUNKS {
        h.update(blob_chunk(i));
    }
    hex::encode(h.finalize())
}

/// Publiziert eine fertige Chunk-Folge in einen Kanal (Reihenfolge 1..N).
pub fn publish_chunks(
    streams: &ChannelRegistry,
    channel: &str,
    chunks: &[Vec<u8>],
) -> Result<usize, ProxyError> {
    streams.open(channel)?;
    for chunk in chunks {
        streams.publish(channel, TYP_MEDIA, chunk.clone())?;
    }
    Ok(chunks.len())
}
