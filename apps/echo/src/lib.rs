//! Echo-App (BEWEIS-App) fuer den Proxy-App-Vertrag v0.
//! no_std, keine Host-Imports: laeuft gastfrei in der z8run-Sandbox.
//! Vertrag: z8_alloc(len) -> ptr, z8_process(ptr,len) -> ptr auf
//! 4-Byte-LE-Laenge + JSON. Antwort: {"ok","app","signature","signed_len",
//! "prompt_used","echo"} — `signature` = SHA-256 ueber die Eingabe-Bytes.

#![no_std]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}

const IN_CAP: usize = 128 * 1024;
const OUT_CAP: usize = 256 * 1024;

static mut IN_BUF: [u8; IN_CAP] = [0; IN_CAP];
static mut OUT_BUF: [u8; OUT_CAP] = [0; OUT_CAP];

#[no_mangle]
pub extern "C" fn z8_alloc(size: i32) -> i32 {
    if size < 0 || size as usize > IN_CAP {
        return -1;
    }
    core::ptr::addr_of_mut!(IN_BUF) as *mut u8 as i32
}

#[no_mangle]
pub extern "C" fn z8_dealloc(_ptr: i32, _len: i32) {}

struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    fn push(&mut self, b: &[u8]) -> bool {
        if self.pos + b.len() > self.buf.len() {
            return false;
        }
        self.buf[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
        true
    }
    fn push_u64(&mut self, mut v: u64) -> bool {
        let mut digits = [0u8; 20];
        let mut i = digits.len();
        loop {
            i -= 1;
            digits[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.push(&digits[i..])
    }
}

#[no_mangle]
pub extern "C" fn z8_process(ptr: i32, len: i32) -> i32 {
    if ptr < 0 || len < 0 || len as usize > IN_CAP {
        return -1;
    }
    let input = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
    let sig = sha256_hex(input);
    let out = unsafe { &mut *core::ptr::addr_of_mut!(OUT_BUF) };
    let base = out.as_mut_ptr();
    let mut w = Writer {
        buf: &mut out[4..],
        pos: 0,
    };
    let mut ok = w.push(b"{\"ok\":true,\"app\":\"echo\",\"signature\":\"");
    ok &= w.push(&sig);
    ok &= w.push(b"\",\"signed_len\":");
    ok &= w.push_u64(len as u64);
    ok &= w.push(b",\"prompt_used\":null,\"echo\":");
    ok &= w.push(input);
    ok &= w.push(b"}");
    if !ok {
        return -1;
    }
    let n = w.pos as u32;
    unsafe {
        core::ptr::copy_nonoverlapping(n.to_le_bytes().as_ptr(), base, 4);
    }
    base as i32
}

fn sha256_hex(data: &[u8]) -> [u8; 64] {
    let digest = sha256(data);
    let mut out = [0u8; 64];
    let hex = b"0123456789abcdef";
    for (i, b) in digest.iter().enumerate() {
        out[i * 2] = hex[(b >> 4) as usize];
        out[i * 2 + 1] = hex[(b & 0x0f) as usize];
    }
    out
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

fn compress(h: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut hh = h[7];
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut i = 0;
    while i + 64 <= data.len() {
        compress(&mut h, &data[i..i + 64]);
        i += 64;
    }
    let rem = data.len() - i;
    let mut block = [0u8; 64];
    block[..rem].copy_from_slice(&data[i..]);
    block[rem] = 0x80;
    if rem >= 56 {
        compress(&mut h, &block);
        block = [0u8; 64];
    }
    let bits = (data.len() as u64).wrapping_mul(8);
    block[56..64].copy_from_slice(&bits.to_be_bytes());
    compress(&mut h, &block);
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}
