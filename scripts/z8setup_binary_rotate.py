#!/usr/bin/env python3
"""S4: Rotation per EXPORTIERTER Setup-API-Binary (ohne z8run)."""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

BASE = os.environ.get("SETUP_HTTP_BASE", "http://127.0.0.1:18124").rstrip("/")
OLD = os.environ.get("SETUP_OLD_PREFIX", "sim2/welt2/z8setup/run7/")
NEW = os.environ.get("SETUP_NEW_PREFIX", "sim2/welt2/z8setup/run7-rot/")
KEYS = os.environ.get("SETUP_KEYS", "/data/z8run-test/verify-logs/z8-setup/s2-world/keys")


def post(path: str, body: dict) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    r = urllib.request.Request(BASE + path, data=data, method="POST")
    r.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=180) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def auth(op: str, space: str) -> dict:
    a = open(f"{KEYS}/setup-hw1.pem").read()
    b = open(f"{KEYS}/setup-hw2.pem").read()
    signed = f"{op}:{space}:{os.urandom(8).hex()}"
    key = serialization.load_pem_private_key(a.encode(), password=None)
    sig = key.sign(signed.encode(), ec.ECDSA(hashes.SHA256()))
    return {"setup_pems": [a, b], "setup_signed": signed,
            "setup_signature": base64.b64encode(sig).decode()}


def main():
    resp = json.load(open("/data/z8run-test/verify-logs/z8-setup/s2-world/response.json"))
    space = resp["space"]
    st, out = post("/rotate-s3", {"newS3": {"prefix": NEW}, "s3": {"prefix": OLD}})
    assert st == 403, (st, out)
    print(f"[1] NEGATIV Binary rotate ohne Setup-Key -> HTTP {st}")
    body = {"newS3": {"prefix": NEW}, "deleteOld": True, "s3": {"prefix": OLD}, **auth("rotate", space)}
    st, out = post("/rotate-s3", body)
    assert st == 200 and out.get("rotation", {}).get("ok"), (st, out)
    print(f"[2] BINARY ROTATE OK objects={out['rotation']['objects']} deleted_old={out['rotation']['deleted_old']} {OLD} -> {NEW}")
    print("== BINARY ROTATE GRUEN ==")


if __name__ == "__main__":
    main()
