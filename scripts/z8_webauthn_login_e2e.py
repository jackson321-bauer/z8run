#!/usr/bin/env python3
"""S2-E2E: KV3-Login-WebAuthn (echtes ES256-Ceremony-Paar) + PEM-Parallelweg.

Startet die exportierten Server-Binaries auf Unix-Sockets, baut eine frische
Welt per Setup-API, registriert ein Software-Passkey (P-256 + ML-KEM-1024),
öffnet den HW-Shard CLIENTSEITIG und ruft /login. Rohlog je Fall.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from z8setup_authenticator import b64url, cb_bytes, cb_int, cb_text  # noqa: E402

BASE = "/data/z8run-test"
LOG = f"{BASE}/verify-logs/z8-webauthn-login"
KEYS = f"{LOG}/s2-client-keys"
EXPORTS = f"{BASE}/exports"
BIN_SETUP = f"{EXPORTS}/bin/z8_Z8_Setup"
BIN_WA = f"{EXPORTS}/bin/z8_Z8_Setup_WebAuthn"
BIN_LOGIN = f"{EXPORTS}/bin/z8_KV3_Login_WebAuthn_server"
BIN_PEM = f"{EXPORTS}/bin/z8_KV3_Login_pem"
SG = "/data/z8run-test/src/target/debug/z8-stahlgitter"
S3 = "/etc/z8run/kv3-s3.json"
PREFIX = "sim2/welt2/z8webauthn/"
SPACE = "z8wa"
RP = "localhost"
ORIGIN = "http://localhost:7700"
SETUP_KEYS = f"/data/z8run/setup-keys/{SPACE}"
PROXY_SOCK = "/data/z8run/kv3-proxy.sock"

SOCK_SETUP = f"{BASE}/z8wa-setup.sock"
SOCK_WA = f"{BASE}/z8wa-webauthn.sock"
SOCK_LOGIN = f"{BASE}/z8wa-login.sock"
SOCK_PEM = f"{BASE}/z8wa-login-pem.sock"

_procs = []
_proxy_body = {}


def log(name: str, obj) -> None:
    with open(f"{LOG}/s2-{name}.json", "w") as f:
        json.dump(obj, f, indent=2)


def unix_post(sock_path: str, path: str, body: dict) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(180)
    s.connect(sock_path)
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
    head, _, payload = raw.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1])
    try:
        parsed = json.loads(payload)
    except Exception:
        parsed = {"raw": payload.decode(errors="replace")}
    return status, parsed


def start(binary: str, sock: str, logname: str) -> subprocess.Popen:
    if os.path.exists(sock):
        os.unlink(sock)
    env = dict(os.environ, Z8_EXPORT_SOCK=sock)
    out = open(f"{LOG}/s2-server-{logname}.log", "w")
    p = subprocess.Popen([binary], env=env, stdout=out, stderr=subprocess.STDOUT)
    _procs.append(p)
    for _ in range(200):
        if os.path.exists(sock):
            return p
        if p.poll() is not None:
            raise SystemExit(f"Server {logname} beendet: siehe s2-server-{logname}.log")
        time.sleep(0.1)
    raise SystemExit(f"Socket {sock} nicht erschienen")


class _Proxy(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("content-length", 0))
        raw = self.rfile.read(n)
        try:
            _proxy_body["session"] = json.loads(raw)
        except Exception:
            _proxy_body["raw"] = raw.decode(errors="replace")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *a):
        pass


def start_proxy():
    if os.path.exists(PROXY_SOCK):
        os.unlink(PROXY_SOCK)
    class S(socketserver.UnixStreamServer):
        def get_request(self):
            req, _ = super().get_request()
            return req, ("local", 0)

        def handle_error(self, request, client_address):
            pass
    srv = S(PROXY_SOCK, _Proxy)
    os.chmod(PROXY_SOCK, 0o666)  # Test-Stuntman; produktiv: gleicher User/Gruppe
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def wipe_prefix() -> int:
    """Frische Test-Welt: alle Objekte NUR unter dem Test-Prefix löschen."""
    import boto3
    c = json.load(open(S3))
    s3 = boto3.client(
        "s3", endpoint_url="https://" + c["host"], region_name=c.get("region", "us-east-1"),
        aws_access_key_id=c["access_key"], aws_secret_access_key=c["secret_key"],
    )
    n = 0
    token = None
    while True:
        kw = {"Bucket": c["bucket"], "Prefix": PREFIX}
        if token:
            kw["ContinuationToken"] = token
        page = s3.list_objects_v2(**kw)
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=c["bucket"], Key=obj["Key"])
            n += 1
        if not page.get("IsTruncated"):
            break
        token = page.get("NextContinuationToken")
    return n


def read_pem(path: str) -> str:
    return open(path).read()


def auth(op: str, nonce: str) -> dict:
    a = read_pem(f"{SETUP_KEYS}/setup-hw1.pem")
    b = read_pem(f"{SETUP_KEYS}/setup-hw2.pem")
    signed = f"{op}:{SPACE}:{nonce}"
    key = serialization.load_pem_private_key(a.encode(), password=None)
    sig = key.sign(signed.encode(), ec.ECDSA(hashes.SHA256()))
    ml = subprocess.check_output(
        [SG, "mldsa-sign", "--key", f"{SETUP_KEYS}/setup-hw1-mldsa.pem", "--msg", signed]
    ).decode().strip()
    return {
        "setup_pems": [a, b],
        "setup_pqc_keys": [f"{SETUP_KEYS}/setup-hw1.kem", f"{SETUP_KEYS}/setup-hw2.kem"],
        "setup_signed": signed,
        "setup_signature": base64.b64encode(sig).decode(),
        "setup_mldsa_signature": ml,
        "s3": {"prefix": PREFIX},
    }


def new_credential(label: str):
    os.makedirs(KEYS, exist_ok=True)
    os.chmod(KEYS, 0o700)
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    pem_path = f"{KEYS}/{label}.pem"
    with open(pem_path, "wb") as f:
        f.write(pem)
    os.chmod(pem_path, 0o600)
    nums = key.public_key().public_numbers()
    x, y = nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big")
    q = json.loads(subprocess.check_output(
        [SG, "pqc-gen", "--dir", KEYS, "--label", label]
    ).decode())
    return key, pem_path, x, y, q["pqc_pub_b64"], q["pqc_dk_path"]


def attestation(key, x, y, cred_id: bytes, challenge: str):
    cose = b"\xa5"
    cose += cb_int(1) + cb_int(2) + cb_int(3) + cb_int(-7) + cb_int(-1) + cb_int(1)
    cose += cb_int(-2) + cb_bytes(x) + cb_int(-3) + cb_bytes(y)
    auth_data = hashlib.sha256(RP.encode()).digest() + bytes([0x41]) + (1).to_bytes(4, "big")
    auth_data += b"\x00" * 16 + len(cred_id).to_bytes(2, "big") + cred_id + cose
    att = b"\xa3" + cb_text("fmt") + cb_text("none") + cb_text("attStmt") + b"\xa0"
    att += cb_text("authData") + cb_bytes(auth_data)
    cd = json.dumps({"type": "webauthn.create", "challenge": challenge, "origin": ORIGIN},
                    separators=(",", ":"))
    return b64url(att), cd


def assertion(key, cred_id: bytes, challenge: str, count: int, origin: str = ORIGIN):
    auth_data = hashlib.sha256(RP.encode()).digest() + bytes([0x01]) + count.to_bytes(4, "big")
    cd = json.dumps({"type": "webauthn.get", "challenge": challenge, "origin": origin},
                    separators=(",", ":"))
    signed = auth_data + hashlib.sha256(cd.encode()).digest()
    sig = key.sign(signed, ec.ECDSA(hashes.SHA256()))
    return {
        "credentialId": b64url(cred_id),
        "authenticatorData": b64url(auth_data),
        "clientDataJSON": b64url(cd.encode()),
        "signature": b64url(sig),
        "challenge": challenge,
    }


def register(user: str, with_pqc: bool = True):
    st, ch = unix_post(SOCK_WA, "/webauthn/challenge", {"user": user, "s3": {"prefix": PREFIX}})
    assert st == 200, (st, ch)
    challenge = ch["webauthn_challenge"]
    label = f"{user}-cred-{'sw' if with_pqc else 'hw'}-{os.urandom(3).hex()}"
    key, pem_path, x, y, pqc_pub, kem = new_credential(label)
    cred_id = os.urandom(16)
    att, cd = attestation(key, x, y, cred_id, challenge)
    body = {
        "user": user,
        "challenge": challenge,
        "rpId": RP,
        "origin": ORIGIN,
        "attestationObject": att,
        "clientDataJSON": b64url(cd.encode()),
        **auth("webauthn-register", os.urandom(6).hex()),
    }
    if with_pqc:
        body["pqc_pub_b64"] = pqc_pub
    st, out = unix_post(SOCK_WA, "/webauthn/register", body)
    assert st == 200 and out.get("ok"), (st, out)
    log(f"register-{user}-{'pqc' if with_pqc else 'hw'}", {
        "status": st,
        "credential_id": out["webauthn_credential"]["credential_id"],
        "key_type": out["webauthn_credential"]["key_type"],
        "has_pqc_pub": bool(out["webauthn_credential"].get("pqc_pub_b64")),
    })
    return key, pem_path, kem, cred_id, out["webauthn_credential"]


def main():
    os.makedirs(LOG, exist_ok=True)
    shutil.rmtree(KEYS, ignore_errors=True)
    os.makedirs(KEYS)
    password = "pw-" + os.urandom(8).hex()
    geloescht = wipe_prefix()
    print(f"[0] Test-Prefix geleert: {geloescht} Objekte")

    start(BIN_SETUP, SOCK_SETUP, "setup")
    start(BIN_WA, SOCK_WA, "webauthn")
    start(BIN_LOGIN, SOCK_LOGIN, "login")
    start(BIN_PEM, SOCK_PEM, "login-pem")
    proxy = start_proxy()

    try:
        st, resp = unix_post(SOCK_SETUP, "/setup", {
            "space": SPACE,
            "s3": {"prefix": PREFIX},
            "users": [{"name": "anna", "password": password, "engines": ["demo"]}],
            "quorum": {"n": 3, "threshold": 2},
        })
        assert st == 200 and resp.get("ok"), (st, resp)
        user = resp["users"][0]
        addr = user["addr_user"]
        expected_master = user["user_master_sha256"]
        log("setup", {"status": st, "space": resp["space"], "addr_user": addr,
                      "expected_master_sha256": expected_master,
                      "users": len(resp["users"]), "secrets_exposed": False})

        # Faktor 2: Software-Passkey (P-256 ES256 + ML-KEM-1024)
        key, pem_path, kem, cred_id, cred = register("anna", with_pqc=True)
        # Hardware-Key (kein PQC/ECDH) registriert, muss WebAuthn-Login verweigern
        hw_key, hw_pem, hw_kem, hw_cred_id, _ = register("anna", with_pqc=False)

        # Faktor 1 + 2: Passwort + Assertion, Shard CLIENTSEITIG geöffnet
        st, ch = unix_post(SOCK_LOGIN, "/challenge", {"user": "anna"})
        assert st == 200, (st, ch)
        a = assertion(key, cred_id, ch["webauthn_challenge"], 2)
        shard = json.loads(subprocess.check_output([
            SG, "shard-open", "--s3-config", S3, "--prefix", PREFIX,
            "--addr", addr, "--key", pem_path, "--kem", kem,
        ]).decode())
        body = {
            "space": SPACE, "user": "anna", "password": password,
            **a, "shamir_hw": shard["shamir_hw"], "s3": {"prefix": PREFIX},
        }
        st, out = unix_post(SOCK_LOGIN, "/login", body)
        log("login-raw", {"status": st, "keys": sorted(out.keys()), "out": out})
        assert st == 200, (st, out)
        assert out["master_sha256"] == expected_master, (out.get("master_sha256"), expected_master)
        assert out["session_view"]["qr_code_uri"].startswith("z8passkey://login/")
        with open(f"{LOG}/s2-qr-uri.txt", "w") as f:
            f.write(out["session_view"]["qr_code_uri"] + "\n")
        subprocess.check_call([
            SG, "qr-svg", "--msg", out["session_view"]["qr_code_uri"],
            "--out", f"{LOG}/s2-qr.svg",
        ])
        assert _proxy_body.get("session", {}).get("master_sha256") == expected_master
        for feld in ("req", "opened_datei", "opened_block", "hw_block"):
            assert feld not in out, f"Secret-/Interna-Leak in Login-Antwort: {feld}"
        assert "password" not in json.dumps(out) and "key_pem" not in json.dumps(out)
        uds = _proxy_body.get("session", {})
        assert "master_key_b64" in uds, "UDS-Body ohne Masterkey-Feld"
        uds_master = hashlib.sha256(base64.b64decode(uds["master_key_b64"])).hexdigest()
        assert uds_master == expected_master, (uds_master, expected_master)
        log("proxy", {"fields": sorted(uds.keys()), "master_key_present": True,
                      "uds_master_sha256": uds_master, "master_key_logged": False,
                      "body_redacted": True})
        log("login-ok", {"status": st, "master_sha256": out["master_sha256"],
                         "expected_master_sha256": expected_master,
                         "uds_master_sha256": uds_master,
                         "response_fields": sorted(out.keys()),
                         "session_view": out["session_view"],
                         "proxy_session_fields": sorted(uds.keys())})
        print(f"[a] LOGIN OK master={out['master_sha256'][:16]} qr={out['session_view']['qr_code_uri']}")

        # (c) PEM-Parallelweg bleibt intakt
        pem_content = read_pem(user["pems"][0]["path"])
        st, out_pem = unix_post(SOCK_PEM, "/login", {
            "space": SPACE, "user": "anna", "password": password, "key_pem": pem_content,
            "pqc_dk_path": user["pems"][0]["pqc_dk_path"],
            "s3": {"prefix": PREFIX},
        })
        assert st == 200 and out_pem.get("master_sha256") == expected_master, (st, out_pem)
        for feld in ("req", "key_pem", "pqc_dk"):
            assert feld not in out_pem, f"Secret-Leak im PEM-Login: {feld}"
        assert "proxy_session" not in out_pem and "master_key_b64" not in json.dumps(out_pem), \
            "PEM-Antwort enthält die UDS-Session/Masterkey"
        log("login-pem-raw", {"status": st, "keys": sorted(out_pem.keys()), "out": out_pem})
        log("login-pem", {"status": st, "master_sha256": out_pem["master_sha256"],
                          "expected_master_sha256": expected_master})
        print(f"[c] PEM-LOGIN OK master={out_pem['master_sha256'][:16]}")

        # (e) Counter-Replay: neue Challenge, gleicher Counter
        st, ch = unix_post(SOCK_LOGIN, "/challenge", {"user": "anna"})
        replay = {"space": SPACE, "user": "anna", "password": password,
                  **assertion(key, cred_id, ch["webauthn_challenge"], 2),
                  "shamir_hw": shard["shamir_hw"], "s3": {"prefix": PREFIX}}
        st, out = unix_post(SOCK_LOGIN, "/login", replay)
        assert st == 401, (st, out)
        log("neg-counter-replay", {"status": st, "error": out.get("error")})
        print(f"[e] NEGATIV Counter-Replay -> {st}")

        # (c) Signatur-Manipulation (1 Byte)
        st, ch = unix_post(SOCK_LOGIN, "/challenge", {"user": "anna"})
        bad = {"space": SPACE, "user": "anna", "password": password,
               **assertion(key, cred_id, ch["webauthn_challenge"], 3, origin="http://evil"),
               "shamir_hw": shard["shamir_hw"], "s3": {"prefix": PREFIX}}
        st, out = unix_post(SOCK_LOGIN, "/login", bad)
        assert st == 401, (st, out)
        log("neg-origin", {"status": st, "error": out.get("error")})
        print(f"[d] NEGATIV Origin -> {st}")

        st, ch = unix_post(SOCK_LOGIN, "/challenge", {"user": "anna"})
        sig_body = {"space": SPACE, "user": "anna", "password": password,
                    **assertion(key, cred_id, ch["webauthn_challenge"], 3),
                    "shamir_hw": shard["shamir_hw"], "s3": {"prefix": PREFIX}}
        raw = base64.urlsafe_b64decode(sig_body["signature"] + "==")
        raw = bytes([raw[0] ^ 1]) + raw[1:]
        sig_body["signature"] = b64url(raw)
        st, out = unix_post(SOCK_LOGIN, "/login", sig_body)
        assert st == 401, (st, out)
        log("neg-signature", {"status": st, "error": out.get("error")})
        print(f"[c] NEGATIV Signatur -> {st}")

        # (b) ohne Assertion
        st, out = unix_post(SOCK_LOGIN, "/login", {
            "space": SPACE, "user": "anna", "password": password,
            "shamir_hw": shard["shamir_hw"], "s3": {"prefix": PREFIX},
        })
        assert st == 401, (st, out)
        log("neg-keyless", {"status": st, "error": out.get("error")})
        print(f"[b] NEGATIV ohne Assertion -> {st}")

        # (d) Hardware-Pubkey ohne ECDH -> 401, klare Meldung (kein stiller Fallback)
        st, ch = unix_post(SOCK_LOGIN, "/challenge", {"user": "anna"})
        hw_body = {"space": SPACE, "user": "anna", "password": password,
                   **assertion(hw_key, hw_cred_id, ch["webauthn_challenge"], 2),
                   "shamir_hw": shard["shamir_hw"], "s3": {"prefix": PREFIX}}
        st, out = unix_post(SOCK_LOGIN, "/login", hw_body)
        assert st == 401, (st, out)
        assert "PEM" in out.get("error", ""), out
        log("neg-hardware", {"status": st, "error": out.get("error")})
        print(f"[d] NEGATIV Hardware ohne ECDH -> {st}: {out.get('error')[:60]}")

        print("== S2 E2E GRUEN ==")
    finally:
        proxy.shutdown()
        for p in _procs:
            p.terminate()
        for p in _procs:
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()
        shutil.rmtree(KEYS, ignore_errors=True)


if __name__ == "__main__":
    main()
