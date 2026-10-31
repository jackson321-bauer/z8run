//! Medien-Frame des Stream-Protokolls (G2): 16-Byte-Header + Rohbytes.
//!
//! Header-Layout (16 B, ALLE Zahlen Little-Endian):
//! `magic u16 | typ u8 | flags u8 | stream_id u32 | seq u64`
//! `len` ist die Laenge hinter dem Header (WS-Nachrichtenrahmen liefert sie
//! exakt; ein zusaetzliches Laengenfeld waere doppelt). Der Proxy liest NUR
//! diesen Header und die Nutzlast bytes — niemals JSON/Codec-Inhalt.

use proxy_kern::ProxyError;

pub const FRAME_MAGIC: u16 = 0x5A38;
pub const HEADER_LEN: usize = 16;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

pub const TYP_MEDIA: u8 = 1;
pub const TYP_REALTIME_JSON: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub typ: u8,
    pub flags: u8,
    pub stream_id: u32,
    pub seq: u64,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(typ: u8, stream_id: u32, seq: u64, payload: Vec<u8>) -> Result<Self, ProxyError> {
        Self::with_flags(typ, 0, stream_id, seq, payload)
    }

    pub fn with_flags(
        typ: u8,
        flags: u8,
        stream_id: u32,
        seq: u64,
        payload: Vec<u8>,
    ) -> Result<Self, ProxyError> {
        if payload.len() > MAX_FRAME_BYTES {
            return Err(ProxyError::Stream(format!(
                "Frame zu gross ({} > {MAX_FRAME_BYTES})",
                payload.len()
            )));
        }
        Ok(Self {
            typ,
            flags,
            stream_id,
            seq,
            payload,
        })
    }

    /// Nutzlastlaenge (das im Header konzeptionell gefuehrte `len`).
    pub fn len(&self) -> usize {
        self.payload.len()
    }

    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    /// Kodiert Header + Rohbytes byte-genau (little endian).
    pub fn encode(&self) -> Result<Vec<u8>, ProxyError> {
        if self.payload.len() > MAX_FRAME_BYTES {
            return Err(ProxyError::Stream("Frame zu gross".into()));
        }
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&FRAME_MAGIC.to_le_bytes());
        out.push(self.typ);
        out.push(self.flags);
        out.extend_from_slice(&self.stream_id.to_le_bytes());
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Liest den Header. Inhalt wird NICHT interpretiert.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProxyError> {
        if bytes.len() < HEADER_LEN {
            return Err(ProxyError::Stream("Frame kuerzer als Header".into()));
        }
        let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
        if magic != FRAME_MAGIC {
            return Err(ProxyError::Stream("Frame-Magic falsch".into()));
        }
        let typ = bytes[2];
        let flags = bytes[3];
        let stream_id = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let seq = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
            bytes[15],
        ]);
        let payload = bytes[HEADER_LEN..].to_vec();
        Self::with_flags(typ, flags, stream_id, seq, payload)
    }
}
