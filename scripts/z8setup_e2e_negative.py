#!/usr/bin/env python3
"""S2-Negativtests: /setup validate + Einmal-Initialisierung (400/409-Ursache)."""

from __future__ import annotations

import json
import os
import socket

SOCK = os.environ.get("Z8_UDS", "/data/z8run/z8run.sock")
FLOW = os.environ.get("Z8_SETUP_FLOW_ID", "01a18762-179c-719c-9bb8-6ea8fb247e72")
EXISTING = os.environ.get("SETUP_EXISTING_PREFIX", "sim2/welt2/z8setup/run8-rot/")


def post(body: dict) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(60)
    s.connect(SOCK)
    s.sendall(
        f"POST /hook/{FLOW}/setup HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
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


def main():
    cases = [
        ("space fehlt", {"users": [{"name": "a", "password": "12345678"}]}),
        ("shared verboten", {"space": "x", "shared": [{"name": "s"}],
                             "users": [{"name": "a", "password": "12345678"}]}),
        ("user doppelt", {"space": "x", "users": [
            {"name": "a", "password": "12345678"},
            {"name": "a", "password": "12345678"}]}),
        ("passwort kurz", {"space": "x", "users": [{"name": "a", "password": "kurz"}]}),
        ("engine unbekannt", {"space": "x", "users": [
            {"name": "a", "password": "12345678", "engines": ["boom"]}]}),
    ]
    for name, body in cases:
        st, out = post(body)
        assert st == 400 and out.get("error"), (name, st, out)
        print(f"[NEG] {name} -> HTTP {st}: {out['error'][:70]}")
    st, out = post({"space": "gamma", "s3": {"prefix": EXISTING},
                    "users": [{"name": "neu", "password": "12345678"}]})
    assert st == 400 and "bereits initialisiert" in out.get("error", ""), (st, out)
    print(f"[NEG] Welt existiert -> HTTP {st}: {out['error'][:70]}")


if __name__ == "__main__":
    main()
