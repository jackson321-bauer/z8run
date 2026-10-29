#!/usr/bin/env python3
"""E2E-Beweis S3: /rotate-s3, /plugin-add, /user-pubkey-add (+ Negativtests)."""

from __future__ import annotations

import base64
import hashlib
import http.cookiejar
import json
import os
import socket
import subprocess
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

BASE = os.environ.get("Z8_BASE_URL", "http://127.0.0.1:7700").rstrip("/")
SOCK = os.environ.get("Z8_EXPORT_UDS") or os.environ.get("Z8_UDS", "/data/z8run/z8run.sock")
EMAIL = os.environ.get("Z8_EMAIL", "")
PASSWORD = os.environ.get("Z8_PASSWORD", "")
OLD = os.environ.get("SETUP_OLD_PREFIX", "sim2/welt2/z8setup/run3/")
NEW = os.environ.get("SETUP_NEW_PREFIX", "sim2/welt2/z8setup/run3-rot/")
MLDSA_BIN = os.environ.get("Z8_MLDSA_BIN", "/data/z8run-test/src/target/release/z8-stahlgitter")
KEYS = os.environ.get("SETUP_KEYS", "/data/z8run-test/verify-logs/z8-setup/s2-world/keys")
RESP = os.environ.get("SETUP_RESP", "/data/z8run-test/verify-logs/z8-setup/s2-world/response.json")
SPEC = os.environ.get("SETUP_SPEC", "/data/z8run-test/verify-logs/z8-setup/s2-world/spec.json")


EXPORT = bool(os.environ.get("Z8_EXPORT_UDS"))
UID = ""


def hp(path: str) -> str:
    return path if EXPORT else f"/hook/{UID}{path}"


def unix_post(path: str, body: dict) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(180)
    s.connect(SOCK)
    s.sendall(
        f"POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode() + data
    )
    raw = b""
    while True:
        c = s.recv(65536)
        if not c:
            break
        raw += c
    s.close()
    head, _, rest = raw.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1])
    try:
        return status, json.loads(rest)
    except Exception:
        return status, {"raw": rest.decode(errors="replace")}


def flow_id(name: str) -> str:
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    data = json.dumps({"email": EMAIL, "password": PASSWORD}).encode()
    r = urllib.request.Request(BASE + "/auth/login", data=data, method="POST")
    r.add_header("content-type", "application/json")
    with op.open(r) as resp:
        cookie = resp.headers.get("set-cookie", "")
    token = next((p.split("=", 1)[1] for p in cookie.split(";") if p.strip().startswith("z8_session=")), "")
    r = urllib.request.Request(BASE + "/api/v1/flows")
    r.add_header("authorization", f"Bearer {token}")
    flows = json.loads(op.open(r).read())["flows"]
    for f in flows:
        if f["name"] == name:
            r = urllib.request.Request(BASE + f"/api/v1/flows/{f['id']}/start", data=b"", method="POST")
            r.add_header("authorization", f"Bearer {token}")
            op.open(r).read()
            return f["id"]
    raise SystemExit(f"Flow {name} fehlt")


def auth(op: str, space: str, extra: dict | None = None) -> dict:
    a = open(f"{KEYS}/setup-hw1.pem").read()
    b = open(f"{KEYS}/setup-hw2.pem").read()
    signed = f"{op}:{space}:{os.urandom(8).hex()}"
    key = serialization.load_pem_private_key(a.encode(), password=None)
    sig = key.sign(signed.encode(), ec.ECDSA(hashes.SHA256()))
    ml = subprocess.check_output([MLDSA_BIN, "mldsa-sign", "--key",
                                  f"{KEYS}/setup-hw1-mldsa.pem", "--msg", signed]).decode().strip()
    out = {
        "setup_pems": [a, b],
        "setup_pqc_keys": [f"{KEYS}/setup-hw1.kem", f"{KEYS}/setup-hw2.kem"],
        "setup_signed": signed,
        "setup_signature": base64.b64encode(sig).decode(),
        "setup_mldsa_signature": ml,
    }
    if extra:
        out.update(extra)
    return out


def hybrid_negativ(path: str, base: dict, label: str):
    for modus in ("nur_ecdsa", "nur_mldsa", "falsch_mldsa"):
        body = dict(base)
        if modus == "nur_ecdsa":
            body.pop("setup_mldsa_signature", None)
        elif modus == "nur_mldsa":
            body.pop("setup_signature", None)
        else:
            raw = bytearray(base64.b64decode(body["setup_mldsa_signature"]))
            raw[0] ^= 1
            body["setup_mldsa_signature"] = base64.b64encode(bytes(raw)).decode()
        st, out = unix_post(path, body)
        assert st == 403, (modus, st, out)
        print(f"[HYBRID-NEG] {label} {modus} -> HTTP {st}")


def main():
    resp = json.load(open(RESP))
    space = resp["space"]
    global UID
    UID = "" if EXPORT else flow_id("Z8-Setup-Operation")

    # --- Rotate: Negativ ohne Key
    body = {"newS3": {"prefix": NEW}, "s3": {"prefix": OLD}}
    st, out = unix_post(hp("/rotate-s3"), body)
    assert st == 403, (st, out)
    print(f"[1] NEGATIV rotate ohne Setup-Key -> HTTP {st}")
    # --- Rotate: Negativ falsche Signatur
    body = {"newS3": {"prefix": NEW}, "s3": {"prefix": OLD}, **auth("rotate", space)}
    body["setup_signature"] = base64.b64encode(b"falsch").decode()
    st, out = unix_post(hp("/rotate-s3"), body)
    assert st == 403, (st, out)
    print(f"[2] NEGATIV rotate falsche Signatur -> HTTP {st}")

    hybrid_negativ(hp("/rotate-s3"),
                   {"newS3": {"prefix": NEW}, "s3": {"prefix": OLD}, **auth("rotate", space)},
                   "rotate")
    # --- Rotate: positiv, inkl. Re-Seal (D4)
    pw = {u["name"]: u["password"] for u in json.load(open(SPEC))["users"]}
    body = {"newS3": {"prefix": NEW}, "deleteOld": True, "rotateBoxes": True,
            "userPasswords": pw, "s3": {"prefix": OLD}, **auth("rotate", space)}
    st, out = unix_post(hp("/rotate-s3"), body)
    assert st == 200 and out.get("rotation", {}).get("ok"), (st, out)
    rot = out["rotation"]
    assert rot["objects"] >= 11, rot
    assert rot.get("resealed", 0) >= 2 and rot.get("resealed_changed") is True, rot
    json.dump(rot, open("/data/z8run-test/verify-logs/z8-setup/s3-rotate.json", "w"), indent=1)
    print(f"[3] ROTATE OK objects={rot['objects']} deleted_old={rot['deleted_old']} "
          f"resealed={rot.get('resealed')} changed={rot.get('resealed_changed')} "
          f"{OLD} -> {NEW} (shards_salts_unchanged={rot['shards_salts_unchanged']})")

    # --- Plugin: Negativ + positiv
    st, out = unix_post(hp("/plugin-add"), {"s3": {"prefix": NEW}, "user": "anna", "plugin": "demo-plugin"})
    assert st == 403, (st, out)
    print(f"[4] NEGATIV plugin ohne Setup-Key -> HTTP {st}")
    bad = {"s3": {"prefix": NEW}, "user": "anna", "plugin": "x", **auth("plugin", space)}
    bad["setup_signature"] = base64.b64encode(b"falsch").decode()
    st, out = unix_post(hp("/plugin-add"), bad)
    assert st == 403, (st, out)
    print(f"[4b] NEGATIV plugin falsche Signatur -> HTTP {st}")
    hybrid_negativ(hp("/plugin-add"),
                   {"s3": {"prefix": NEW}, "user": "anna", "plugin": "x", **auth("plugin", space)},
                   "plugin")
    for plug in ("demo-plugin", "vec-plugin"):
        body = {"s3": {"prefix": NEW}, "user": "anna", "plugin": plug, **auth("plugin", space)}
        st, out = unix_post(hp("/plugin-add"), body)
        assert st == 200 and out.get("plugin", {}).get("ok"), (st, out)
        assert plug in out["plugin"]["plugins"], out
        print(f"[5] PLUGIN OK anna += {plug} -> {out['plugin']['plugins']} sha={out['plugin']['hashdatei_sha256'][:12]}")

    # --- Pubkey: Negativ + positiv
    st, out = unix_post(hp("/user-pubkey-add"), {"s3": {"prefix": NEW}, "user": "bernd",
                                                         "pub_b64": "x"})
    assert st == 403, (st, out)
    print(f"[6] NEGATIV pubkey ohne Setup-Key -> HTTP {st}")
    bad = {"s3": {"prefix": NEW}, "user": "bernd", "pub_b64": "x", **auth("pubkey", space)}
    bad["setup_signature"] = base64.b64encode(b"falsch").decode()
    st, out = unix_post(hp("/user-pubkey-add"), bad)
    assert st == 403, (st, out)
    print(f"[6b] NEGATIV pubkey falsche Signatur -> HTTP {st}")
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    pub = b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption()).decode()
    pem_path = f"{KEYS}/bernd-hw3.pem"
    open(pem_path, "w").write(pem)
    os.chmod(pem_path, 0o600)
    pq = json.loads(subprocess.check_output(
        [MLDSA_BIN, "pqc-gen", "--dir", KEYS, "--label", "bernd-hw3"]).decode())
    body = {"s3": {"prefix": NEW}, "user": "bernd", "name": "bernd-hw3",
            "pub_b64": base64.b64encode(pub).decode(),
            "pqc_pub_b64": pq["pqc_pub_b64"], **auth("pubkey", space)}
    hybrid_negativ(hp("/user-pubkey-add"), dict(body, **auth("pubkey", space)), "pubkey")
    st, out = unix_post(hp("/user-pubkey-add"), body)
    assert st == 200 and out.get("pubkey_added", {}).get("ok"), (st, out)
    added = out["pubkey_added"]
    print(f"[7] PUBKEY OK bernd block={added['block']} pub={added['pub_b64'][:12]} sha={added['hw_shards_sha256'][:12]}")
    print("== OPERATION E2E GRUEN ==")


if __name__ == "__main__":
    main()
