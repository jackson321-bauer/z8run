#!/usr/bin/env python3
"""Live-E2E PROXY-1: Login-Handoff (unix-out/HTTP + raw line), Token,
DB-Scope, Echo-App, LLM-Prompt-Injektion, Streams, Logout."""

from __future__ import annotations

import hashlib
import http.client
import json
import socket
import subprocess
import threading
import time

SOCK = "/data/z8run/kv3-proxy.sock"
HOST = "127.0.0.1"
PORT = 7800
MASTER = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="
PROMPT = "PROXY-DEMO-SYSTEMPROMPT-2026"
CHUNKS = 12
CHUNK = 1024 * 1024
STRIDE = CHUNK + 4


def proxy_pid() -> int:
    out = subprocess.check_output(
        ["systemctl", "show", "-p", "MainPID", "--value", "kv-proxy"], text=True
    ).strip()
    return int(out)


def rss_kb(pid: int) -> int:
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return 0


def uds(uri: str, body: dict, http_mode: bool = True) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect(SOCK)
    raw = json.dumps(body).encode()
    if http_mode:
        req = (
            f"POST {uri} HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\n"
            f"content-length: {len(raw)}\r\nconnection: close\r\n\r\n"
        ).encode() + raw
    else:
        req = raw + b"\n"
    s.sendall(req)
    data = b""
    while True:
        part = s.recv(65536)
        if not part:
            break
        data += part
    s.close()
    if http_mode:
        _, _, payload = data.partition(b"\r\n\r\n")
    else:
        payload = data.strip()
    return json.loads(payload)


def api(method: str, path: str, token: str, body: dict | None = None) -> tuple[int, dict]:
    conn = http.client.HTTPConnection(HOST, PORT, timeout=120)
    headers = {"authorization": f"Bearer {token}"}
    payload = json.dumps(body) if body is not None else None
    if payload:
        headers["content-type"] = "application/json"
    conn.request(method, path, body=payload, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, json.loads(raw) if raw else {}


def main() -> int:
    login = {
        "event": "kv3-session",
        "trace_id": "e2e-proxy",
        "addr_space": "proxy-e2e",
        "addr_user": "e2e-user",
        "master_key_b64": MASTER,
        "master_sha256": "nur-fingerprint",
        "workspace_bucket": "workspaces/proxy-e2e/",
        "engines": ["demo"],
        "dbs": ["demo", "meta"],
    }
    reply = uds("/session", login, http_mode=True)
    assert reply.get("ok") is True, reply
    token = reply["token"]
    assert reply["dbs"] == ["demo", "meta"], reply
    print(f"LOGIN_HTTP ok=1 session={reply['session_id']} dbs={reply['dbs']}")

    raw_reply = uds("/", login, http_mode=False)
    assert raw_reply.get("ok") is True, raw_reply
    print("LOGIN_RAW ok=1")

    status, s = api("GET", "/v1/session", token)
    assert status == 200 and s["session_id"] == reply["session_id"], (status, s)
    print(f"SESSION ok=1 user={s['addr_user']}")

    status, rows = api(
        "POST",
        "/v1/db/query",
        token,
        {"db_id": "demo", "sql": "SELECT 1 AS ok", "readonly": True},
    )
    assert status == 200, (status, rows)
    assert rows.get("columns") == ["ok"] and rows.get("rows") == [[1]], rows
    print(f"DB_QUERY rows={rows['rows']}")

    status, err = api(
        "POST",
        "/v1/db/query",
        token,
        {"db_id": "fremd", "sql": "SELECT 1", "readonly": True},
    )
    assert status == 403 and err.get("code") == "NOT_IN_SCOPE", (status, err)
    print("SCOPE foreign=403 NOT_IN_SCOPE")

    status, apps = api("GET", "/v1/apps", token)
    assert status == 200 and any(a["name"] == "echo" for a in apps["apps"]), apps
    print(f"APP_LIST apps={[a['name'] for a in apps['apps']]}")

    inp = {"msg": "hallo live", "n": 42}
    status, out = api("POST", "/v1/app/call", token, {"app": "echo", "input": inp})
    assert status == 200, (status, out)
    assert out["payload"]["echo"] == inp and out["payload"]["ok"] is True, out
    expect = hashlib.sha256(json.dumps(inp, separators=(",", ":")).encode()).hexdigest()
    assert out["payload"]["signature"] == expect, (out["payload"]["signature"], expect)
    assert PROMPT not in json.dumps(out), "Prompt in App-Antwort"
    print(f"ECHO ok=1 signature_sha256={expect[:16]}...")

    status, llm = api("POST", "/v1/llm/call", token, {"prompt": "system_demo", "user": "frage"})
    assert status == 200 and llm["system_injected"] is True, (status, llm)
    assert PROMPT not in json.dumps(llm), "Prompt in LLM-Antwort"
    print(f"LLM system_injected=1 chars={llm['system_chars']} prompt_visible=0")

    status, meta = api("GET", "/v1/stream/blob/meta", token)
    assert status == 200 and meta["chunks"] == CHUNKS, meta
    pid = proxy_pid()
    before = rss_kb(pid)
    peak = {"kb": before}
    stop = threading.Event()

    def sample() -> None:
        while not stop.is_set():
            peak["kb"] = max(peak["kb"], rss_kb(pid))
            time.sleep(0.01)

    th = threading.Thread(target=sample, daemon=True)
    th.start()
    conn = http.client.HTTPConnection(HOST, PORT, timeout=120)
    conn.request("GET", "/v1/stream/blob", headers={"authorization": f"Bearer {token}"})
    resp = conn.getresponse()
    assert resp.status == 200
    body = bytearray()
    while True:
        part = resp.read(65536)
        if not part:
            break
        body += part
    conn.close()
    stop.set()
    th.join(timeout=1)
    growth = peak["kb"] - before
    assert hashlib.sha256(body).hexdigest() == meta["sha256"], "sha ungleich"
    order = [int.from_bytes(body[i * STRIDE : i * STRIDE + 4], "little") for i in range(CHUNKS)]
    assert order == list(range(1, CHUNKS + 1)), order
    assert growth < 5 * 1024, growth
    print(f"BLOB sha_ok=1 order={order} rss_growth_kb={growth}")

    conn = http.client.HTTPConnection(HOST, PORT, timeout=60)
    conn.request("GET", "/v1/stream/events", headers={"authorization": f"Bearer {token}"})
    resp = conn.getresponse()
    raw = resp.read().decode()
    conn.close()
    seqs = [
        json.loads(line[len("data: ") :])["seq"]
        for line in raw.splitlines()
        if line.startswith("data: ")
    ]
    assert seqs == list(range(1, CHUNKS + 1)), seqs
    print(f"SSE seqs={seqs}")

    status, _ = api("POST", "/v1/session/logout", token)
    assert status == 200, status
    status, _ = api("GET", "/v1/session", token)
    assert status == 401, status
    print("LOGOUT ok=1 token_dead=1")
    print("RESULT PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
