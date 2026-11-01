"""udsv3-Client fuer MCP-Skripte (UDS, AES-GCM, Counter, zufaellige Nonce).

Frame: u32 len | u64 counter | 12 nonce | u32 ct_len | ciphertext.
Schluessel: HKDF-SHA256(Master, salt=b"z8-udsv3", info="udsv3|<ctx>").
Master: /data/z8run/udsv3.key (0600) oder Z8_UDSV3_MASTER (hex/b64).
"""
import base64
import json
import os
import socket
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _master() -> bytes:
    raw = os.environ.get("Z8_UDSV3_MASTER", "").strip()
    if raw:
        try:
            return bytes.fromhex(raw.removeprefix("0x"))
        except ValueError:
            return base64.b64decode(raw)
    with open(os.environ.get("Z8_UDSV3_KEYFILE", "/data/z8run/udsv3.key"), "rb") as f:
        b = f.read()
    if len(b) == 32:
        return b
    t = b.decode().strip()
    try:
        return bytes.fromhex(t.removeprefix("0x"))
    except ValueError:
        return base64.b64decode(t)


def _key(ctx: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"z8-udsv3",
                info=("udsv3|" + ctx).encode()).derive(_master())


def _frame(key: bytes, ctx: str, counter: int, plain: bytes) -> bytes:
    nonce = os.urandom(12)
    aad = ctx.encode() + struct.pack(">Q", counter)
    ct = AESGCM(key).encrypt(nonce, plain, aad)
    body = struct.pack(">Q", counter) + nonce + struct.pack(">I", len(ct)) + ct
    return struct.pack(">I", len(body)) + body


def _read_exact(s: socket.socket, n: int) -> bytes:
    out = b""
    while len(out) < n:
        c = s.recv(n - len(out))
        if not c:
            raise EOFError("udsv3: Verbindung vor Frame-Ende geschlossen")
        out += c
    return out


def _read_frame(s: socket.socket, key: bytes, ctx: str) -> bytes:
    ln = struct.unpack(">I", _read_exact(s, 4))[0]
    body = _read_exact(s, ln)
    counter = struct.unpack(">Q", body[:8])[0]
    nonce = body[8:20]
    ct = body[24:]
    aad = ctx.encode() + struct.pack(">Q", counter)
    return AESGCM(key).decrypt(nonce, ct, aad)


def post(sock: str, ctx: str, path: str, body: dict, timeout: float = 300.0) -> tuple[int, dict]:
    key = _key(ctx)
    payload = json.dumps(body).encode()
    req = (b"POST " + path.encode() + b" HTTP/1.1\r\nhost: localhost\r\n"
           b"content-type: application/json\r\nconnection: close\r\n"
           b"content-length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload)
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(timeout)
    s.connect(sock)
    s.sendall(_frame(key, ctx, 0, req))
    raw = b""
    try:
        while True:
            raw += _read_frame(s, key, ctx)
    except EOFError:
        pass
    finally:
        s.close()
    head, _, text = raw.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1]) if head else 0
    try:
        return status, json.loads(text)
    except ValueError:
        return status, {"raw": text[:2000].decode(errors="replace")}
