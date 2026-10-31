#!/usr/bin/env python3
"""S4/S5 E2E: 12-Chunk-Blob durch den Proxy (sha256, Reihenfolge, RSS) + SSE.

Erzeugt eine Admin-Session ueber den 0600-UDS (open_dbs=false), streamt den
deterministischen Blob und misst den RSS des Proxy-Prozesses waehrenddessen.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import socket
import threading
import time

CHUNKS = 12
CHUNK = 1024 * 1024
STRIDE = CHUNK + 4


def rss_kb(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return 0


def uds_http(path: str, method: str, uri: str, body: bytes | None = None) -> tuple[int, dict]:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(path)
    head = f"{method} {uri} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n"
    if body is not None:
        head += f"content-type: application/json\r\ncontent-length: {len(body)}\r\n"
    s.sendall(head.encode() + b"\r\n" + (body or b""))
    data = b""
    while True:
        part = s.recv(65536)
        if not part:
            break
        data += part
    s.close()
    raw_head, _, raw_body = data.partition(b"\r\n\r\n")
    status = int(raw_head.split(b" ")[1])
    return status, json.loads(raw_body or b"{}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=7800)
    ap.add_argument("--admin", default="/data/z8run/kv-proxy-admin.sock")
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--addr-space", default="e2e-stream")
    args = ap.parse_args()

    master = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="
    status, session = uds_http(
        args.admin,
        "POST",
        "/v1/admin/session",
        json.dumps(
            {
                "addr_space": args.addr_space,
                "addr_user": "e2e",
                "master_key_b64": master,
                "dbs": ["demo"],
                "open_dbs": False,
            }
        ).encode(),
    )
    assert status == 200, (status, session)
    token = session["token"]
    auth = {"authorization": f"Bearer {token}"}

    conn = http.client.HTTPConnection("127.0.0.1", args.port, timeout=120)
    conn.request("GET", "/v1/stream/blob/meta", headers=auth)
    meta = json.loads(conn.getresponse().read())
    conn.close()
    assert meta["chunks"] == CHUNKS, meta
    assert meta["total"] == CHUNKS * STRIDE, meta
    print(f"META chunks={meta['chunks']} total={meta['total']} sha={meta['sha256']}")

    before = rss_kb(args.pid)
    peak = {"kb": before}
    stop = threading.Event()

    def sample() -> None:
        while not stop.is_set():
            peak["kb"] = max(peak["kb"], rss_kb(args.pid))
            time.sleep(0.01)

    t = threading.Thread(target=sample, daemon=True)
    t.start()

    conn = http.client.HTTPConnection("127.0.0.1", args.port, timeout=120)
    conn.request("GET", "/v1/stream/blob", headers=auth)
    resp = conn.getresponse()
    assert resp.status == 200, resp.status
    body = bytearray()
    while True:
        part = resp.read(65536)
        if not part:
            break
        body += part
    conn.close()
    stop.set()
    t.join(timeout=1)
    after = rss_kb(args.pid)

    sha = hashlib.sha256(body).hexdigest()
    assert sha == meta["sha256"], (sha, meta["sha256"])
    assert len(body) == meta["total"], (len(body), meta["total"])
    order = []
    for i in range(CHUNKS):
        idx = int.from_bytes(body[i * STRIDE : i * STRIDE + 4], "little")
        order.append(idx)
        fill = body[i * STRIDE + 4 : (i + 1) * STRIDE]
        assert all(b == (((i & 0xFF) + 1) | 0x80) for b in fill[:4096]), i
    assert order == list(range(CHUNKS)), order
    print(f"BLOB order={order} sha_ok=1 bytes={len(body)}")
    growth = peak["kb"] - before
    print(f"RSS before_kb={before} peak_kb={peak['kb']} after_kb={after} growth_kb={growth}")
    assert growth < 5 * 1024, f"RSS-Anstieg {growth} KiB >= 5 MB"

    conn = http.client.HTTPConnection("127.0.0.1", args.port, timeout=60)
    conn.request("GET", "/v1/stream/events", headers=auth)
    resp = conn.getresponse()
    assert resp.status == 200
    text = resp.read().decode()
    conn.close()
    seqs = [
        json.loads(line[len("data: ") :])["seq"]
        for line in text.splitlines()
        if line.startswith("data: ")
    ]
    assert seqs == list(range(1, CHUNKS + 1)), seqs
    print(f"SSE seqs={seqs}")
    print("RESULT PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
