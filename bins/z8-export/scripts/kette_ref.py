#!/usr/bin/env python3
"""Independent reference chain for the S3c login proof.

Docs: docs/z8-export.md. Reads the KronVault world-2 files (canonical S3
snapshot), opens passbox + hardware box with the real parameters and
recomputes the master key. Prints hex(master) and sha256(master); the z8
flow must return sha256(master) and the fixture stores hex(master).

Usage:
  python3 kette_ref.py <space> <user> <password> <key.pem> [base_dir]

Requires the Hermes venv (argon2-cffi + cryptography):
  /root/hermes-venv/bin/python3 kette_ref.py space-alpha anna anna-test-1 \
      /data/kronvault/kronvault-bucket-konzept/welt2/keys/anna-hw1.pem
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes as H
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

B64 = base64.b64decode
DEFAULT_BASE = Path("/data/kronvault/kronvault-bucket-konzept/welt2")


def sha_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def argon2_raw(password: str, salt: str) -> bytes:
    return hash_secret_raw(
        password.encode(),
        salt.encode(),
        time_cost=2,
        memory_cost=19456,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )


def read_blocks(path: Path) -> list[str]:
    text = path.read_text().split("Encrypted", 1)[1]
    blocks: list[str] = []
    current: list[str] = []
    collecting = False
    for line in text.splitlines():
        line = line.strip()
        if line == "Anfang":
            collecting = True
        elif line == "Ende":
            break
        elif not collecting:
            continue
        elif line.startswith("Block-"):
            if current:
                blocks.append("".join(current))
                current = []
        elif line:
            current.append(line)
    if current:
        blocks.append("".join(current))
    return blocks


def load_priv(pem: str) -> ec.EllipticCurvePrivateKey:
    body = "".join(l.strip() for l in pem.splitlines() if not l.startswith("-----"))
    der = B64(body)
    # SEC1: 30 len 02 01 01 04 20 <32-byte scalar> ...
    return ec.derive_private_key(int.from_bytes(der[7:39], "big"), ec.SECP256R1())


def open_passbox(box: dict, password: str, salt: str) -> dict:
    key = argon2_raw(password, salt)
    plain = AESGCM(key).decrypt(B64(box["nonce"]), B64(box["box"]), box["aad"].encode())
    return json.loads(plain)


def open_hw(box: dict, pem: str) -> dict:
    priv = load_priv(pem)
    ephem = B64(box["ephem"])
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ephem)
    shared = priv.exchange(ec.ECDH(), pub)
    key = HKDF(algorithm=H.SHA256(), length=32, salt=ephem, info=b"kv-m2-secretbox").derive(shared)
    plain = AESGCM(key).decrypt(B64(box["nonce"]), B64(box["box"]), box["aad"].encode())
    return json.loads(plain)


def gf_mul(a: int, b: int) -> int:
    p = 0
    while b:
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def gf_inv(a: int) -> int:
    r, base = 1, a
    for _ in range(7):
        base = gf_mul(base, base)
        r = gf_mul(r, base)
    return r


def combine2(a: tuple[int, bytes], b: tuple[int, bytes]) -> bytes:
    xa, ya = a
    xb, yb = b
    la = gf_mul(xb, gf_inv(xa ^ xb))
    lb = gf_mul(xa, gf_inv(xa ^ xb))
    return bytes(gf_mul(y, la) ^ gf_mul(z, lb) for y, z in zip(ya, yb))


def share(obj: dict) -> tuple[int, bytes]:
    for key in ("shamir_provider", "shamir_hw", "shard"):
        if key in obj:
            obj = obj[key]
            break
    return int(obj["x"]), B64(obj["y"])


def main() -> int:
    if len(sys.argv) < 5:
        print(__doc__)
        return 2
    space, user, password, pem_path = sys.argv[1:5]
    base = Path(sys.argv[5]) if len(sys.argv) > 5 else DEFAULT_BASE

    salt_space = sha_hex(f"kv3-salt:{space}".encode())
    salt_user = sha_hex(f"{salt_space}:user:{user}".encode())
    space_addr = base64.b32encode(argon2_raw(space, salt_space)).decode().lower()[:32]
    user_addr = base64.b32encode(argon2_raw(user, salt_user)).decode().lower()[:32]

    passbox = json.loads(B64(read_blocks(base / "b2b-A" / f"{user_addr}.txt")[0]))
    provider = share(open_passbox(passbox, password, salt_user))

    pem = Path(pem_path).read_text()
    hw = None
    for block in read_blocks(base / "workspaces" / user_addr / "hw-shards.txt"):
        try:
            hw = share(open_hw(json.loads(B64(block)), pem))
            break
        except Exception:
            continue
    if hw is None:
        print("hardware key does not open any box", file=sys.stderr)
        return 1

    master = combine2(provider, hw)
    result = {
        "space_addr": space_addr,
        "user_addr": user_addr,
        "master_hex": master.hex(),
        "sha256_master": sha_hex(master),
    }
    fixture = base / "zugangsdaten" / "fixture.json"
    if fixture.is_file():
        users = {u["name"]: u for u in json.loads(fixture.read_text())["users"]}
        result["fixture_match"] = users.get(user, {}).get("master_sha256") == result["master_hex"]
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
