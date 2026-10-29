//! Minimaler CBOR-Decoder für WebAuthn-Attestation/Authenticator-Data.
//! Nur definite Längen — genau das, was WebAuthn-Clients senden.

pub enum Cbor {
    UInt(u64),
    NInt(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Bool(bool),
    Null,
}

impl Cbor {
    pub fn get(&self, key: &str) -> Option<&Cbor> {
        match self {
            Cbor::Map(entries) => entries.iter().find_map(|(k, v)| match k {
                Cbor::Text(t) if t == key => Some(v),
                _ => None,
            }),
            _ => None,
        }
    }

    pub fn get_int(&self, key: i64) -> Option<i64> {
        match self {
            Cbor::Map(entries) => entries.iter().find_map(|(k, v)| {
                let kk = match k {
                    Cbor::UInt(u) => Some(*u as i64),
                    Cbor::NInt(n) => Some(*n),
                    _ => None,
                };
                if kk == Some(key) {
                    match v {
                        Cbor::UInt(u) => Some(*u as i64),
                        Cbor::NInt(n) => Some(*n),
                        _ => None,
                    }
                } else {
                    None
                }
            }),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Cbor::Text(t) => Some(t),
            _ => None,
        }
    }

    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Cbor::UInt(u) => Some(*u),
            _ => None,
        }
    }
}

fn read_len(buf: &[u8], pos: &mut usize, info: u8, len: usize) -> Result<u64, String> {
    let need = |n: usize| -> Result<(), String> {
        if *pos + n > len {
            Err("CBOR: zu kurz".into())
        } else {
            Ok(())
        }
    };
    let v = match info {
        0..=23 => info as u64,
        24 => {
            need(1)?;
            buf[*pos] as u64
        }
        25 => {
            need(2)?;
            u16::from_be_bytes([buf[*pos], buf[*pos + 1]]) as u64
        }
        26 => {
            need(4)?;
            u32::from_be_bytes([buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]]) as u64
        }
        27 => {
            need(8)?;
            let mut a = [0u8; 8];
            a.copy_from_slice(&buf[*pos..*pos + 8]);
            u64::from_be_bytes(a)
        }
        _ => return Err("CBOR: indefinite Länge nicht unterstützt".into()),
    };
    *pos += match info {
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => 0,
    };
    Ok(v)
}

pub fn decode(buf: &[u8]) -> Result<Cbor, String> {
    let mut pos = 0usize;
    let v = decode_at(buf, &mut pos, 0)?;
    Ok(v)
}

fn decode_at(buf: &[u8], pos: &mut usize, depth: usize) -> Result<Cbor, String> {
    if depth > 32 || *pos >= buf.len() {
        return Err("CBOR: Tiefe/Ende".into());
    }
    let head = buf[*pos];
    *pos += 1;
    let major = head >> 5;
    let info = head & 0x1f;
    if major == 7 {
        return match info {
            20 => Ok(Cbor::Bool(false)),
            21 => Ok(Cbor::Bool(true)),
            22 => Ok(Cbor::Null),
            _ => Err("CBOR: simple value".into()),
        };
    }
    let n = read_len(buf, pos, info, buf.len())? as usize;
    match major {
        0 => Ok(Cbor::UInt(n as u64)),
        1 => Ok(Cbor::NInt(-1 - n as i64)),
        2 => {
            if *pos + n > buf.len() {
                return Err("CBOR: bytes zu kurz".into());
            }
            let b = buf[*pos..*pos + n].to_vec();
            *pos += n;
            Ok(Cbor::Bytes(b))
        }
        3 => {
            if *pos + n > buf.len() {
                return Err("CBOR: text zu kurz".into());
            }
            let s = String::from_utf8(buf[*pos..*pos + n].to_vec())
                .map_err(|e| format!("CBOR text: {e}"))?;
            *pos += n;
            Ok(Cbor::Text(s))
        }
        4 => {
            let mut arr = Vec::with_capacity(n.min(64));
            for _ in 0..n {
                arr.push(decode_at(buf, pos, depth + 1)?);
            }
            Ok(Cbor::Array(arr))
        }
        5 => {
            let mut map = Vec::with_capacity(n.min(64));
            for _ in 0..n {
                let k = decode_at(buf, pos, depth + 1)?;
                let v = decode_at(buf, pos, depth + 1)?;
                map.push((k, v));
            }
            Ok(Cbor::Map(map))
        }
        _ => Err("CBOR: major type".into()),
    }
}
