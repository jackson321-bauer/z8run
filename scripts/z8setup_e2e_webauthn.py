#!/usr/bin/env python3
"""E2E-Beweis WebAuthn/FIDO2 im Z8-Setup (Software-Authenticator, ES256).

Ruft die laufenden Setup-Flows über den Unix-Socket-Hook auf. Keine Secrets
im Skript; PEM-/Response-Pfade kommen aus der Umgebung.
"""

from __future__ import annotations

import base64
import hashlib
import http.cookiejar
import json
import os
import socket
import sys
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

BASE = os.environ.get("Z8_BASE_URL", "http://127.0.0.1:7700").rstrip("/")
SOCK = os.environ.get("Z8_UDS", "/data/z8run/z8run.sock")
EMAIL = os.environ.get("Z8_EMAIL", "")
PASSWORD = os.environ.get("Z8_PASSWORD", "")
PREFIX = os.environ.get("SETUP_PREFIX", "sim2/welt2/z8setup/run2/")
KEYS = os.environ.get("SETUP_KEYS", "/data/z8run-test/verify-logs/z8-setup/s2-world/keys")
RESP = os.environ.get("SETUP_RESP", "/data/z8run-test/verify-logs/z8-setup/s2-world/response.json")



from z8setup_authenticator import b64url, cb_bytes, cb_head, cb_int, cb_text


def unix_post(path: str, body: dict) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(120)
    s.connect(SOCK)
    s.sendall(
        f"POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode() + data
    )
    raw = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        raw += chunk
    s.close()
    head, _, body_raw = raw.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1])
    try:
        parsed = json.loads(body_raw)
    except Exception:
        parsed = {"raw": body_raw.decode(errors="replace")}
    return status, parsed


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


def setup_pems() -> tuple[str, str]:
    a = open(f"{KEYS}/setup-hw1.pem").read()
    b = open(f"{KEYS}/setup-hw2.pem").read()
    return a, b


def signierte_auth(op: str, space: str, nonce: str) -> dict:
    a, b = setup_pems()
    signed = f"{op}:{space}:{nonce}"
    key = serialization.load_pem_private_key(a.encode(), password=None)
    sig = key.sign(signed.encode(), ec.ECDSA(hashes.SHA256()))
    return {
        "setup_pems": [a, b],
        "setup_signed": signed,
        "setup_signature": base64.b64encode(sig).decode(),
        "s3": {"prefix": PREFIX},
    }


def registriere(uid: str, space: str, user: str):
    st, ch = unix_post(f"/hook/{uid}/webauthn/challenge", {"user": user})
    assert st == 200, (st, ch)
    challenge, rp, origin = ch["webauthn_challenge"], ch["rp_id"], ch["origin"]
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    x, y = nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big")
    cred_id = os.urandom(16)
    cose = b"\xa5"
    cose += cb_int(1) + cb_int(2) + cb_int(3) + cb_int(-7) + cb_int(-1) + cb_int(1)
    cose += cb_int(-2) + cb_bytes(x) + cb_int(-3) + cb_bytes(y)
    auth = hashlib.sha256(rp.encode()).digest() + bytes([0x41]) + (1).to_bytes(4, "big")
    auth += b"\x00" * 16 + len(cred_id).to_bytes(2, "big") + cred_id + cose
    att = b"\xa3" + cb_text("fmt") + cb_text("none") + cb_text("attStmt") + b"\xa0" + cb_text("authData") + cb_bytes(auth)
    cd = json.dumps({"type": "webauthn.create", "challenge": challenge, "origin": origin}, separators=(",", ":"))
    body = {
        "user": user,
        "challenge": challenge,
        "rpId": rp,
        "origin": origin,
        "attestationObject": b64url(att),
        "clientDataJSON": b64url(cd.encode()),
        **signierte_auth("webauthn-register", space, os.urandom(6).hex()),
    }
    st, out = unix_post(f"/hook/{uid}/webauthn/register", body)
    assert st == 200 and out.get("ok"), (st, out)
    cred = out["webauthn_credential"]
    assert cred["credential_id"] == b64url(cred_id), (cred["credential_id"], b64url(cred_id))
    pub_sec1 = b"\x04" + x + y
    assert cred["pub_b64"] == base64.b64encode(pub_sec1).decode(), "registrierter Pubkey falsch"
    return key, cred_id, rp, origin


def assertion(uid: str, space: str, user: str, key, cred_id: bytes, rp: str, origin: str):
    st, ch = unix_post(f"/hook/{uid}/webauthn/challenge", {"user": user})
    challenge = ch["webauthn_challenge"]
    auth = hashlib.sha256(rp.encode()).digest() + bytes([0x01]) + (2).to_bytes(4, "big")
    cd = json.dumps({"type": "webauthn.get", "challenge": challenge, "origin": origin}, separators=(",", ":"))
    signed = auth + hashlib.sha256(cd.encode()).digest()
    sig = key.sign(signed, ec.ECDSA(hashes.SHA256()))
    key.public_key().verify(sig, signed, ec.ECDSA(hashes.SHA256()))
    body = {
        "user": user,
        "challenge": challenge,
        "rpId": rp,
        "origin": origin,
        "credentialId": b64url(cred_id),
        "authenticatorData": b64url(auth),
        "clientDataJSON": b64url(cd.encode()),
        "signature": b64url(sig),
        **signierte_auth("webauthn-assert", space, os.urandom(6).hex()),
    }
    st, out = unix_post(f"/hook/{uid}/webauthn/assert", body)
    assert st == 200 and out.get("webauthn_assertion", {}).get("ok"), (st, out)
    return out["webauthn_assertion"]


def main():
    resp = json.load(open(RESP))
    space = resp["space"]
    uid = flow_id("Z8-Setup-WebAuthn")
    for user in resp["users"]:
        name = user["name"]
        key, cred_id, rp, origin = registriere(uid, space, name)
        print(f"[1] WEBAUTHN REGISTER OK {name} cred={b64url(cred_id)[:12]}")
        out = assertion(uid, space, name, key, cred_id, rp, origin)
        print(f"[2] WEBAUTHN ASSERT OK {name} sign_count={out['sign_count']}")

    # Negativtest: ohne Setup-Key -> 403
    st, ch = unix_post(f"/hook/{uid}/webauthn/challenge", {"user": "anna"})
    body = {"user": "anna", "challenge": ch["webauthn_challenge"], "rpId": ch["rp_id"],
            "origin": ch["origin"], "attestationObject": "", "clientDataJSON": "", "s3": {"prefix": PREFIX}}
    st, out = unix_post(f"/hook/{uid}/webauthn/register", body)
    assert st == 403, (st, out)
    print(f"[3] NEGATIV OK ohne Setup-Key -> HTTP {st}")

    # Negativtest: falsche Signatur -> 403
    a, b = setup_pems()
    body = {"user": "anna", "challenge": ch["webauthn_challenge"], "rpId": ch["rp_id"],
            "origin": ch["origin"], "attestationObject": "", "clientDataJSON": "",
            "setup_pems": [a, b], "setup_signed": f"webauthn-register:{space}:x",
            "setup_signature": base64.b64encode(b"falsch").decode(), "s3": {"prefix": PREFIX}}
    st, out = unix_post(f"/hook/{uid}/webauthn/register", body)
    assert st == 403, (st, out)
    print(f"[4] NEGATIV OK falsche Signatur -> HTTP {st}")
    print("== WEBAUTHN E2E GRUEN ==")


if __name__ == "__main__":
    main()
