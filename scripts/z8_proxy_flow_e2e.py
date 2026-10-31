#!/usr/bin/env python3
"""E2E: Demo-Flow im Canvas (login-handoff -> kv-proxy -> db-query -> Antwort)
ueber den z8run-UDS-Trigger ausfuehren."""
from __future__ import annotations

import http.client
import http.cookiejar
import json
import socket
import urllib.request
from pathlib import Path

ENV = Path("/etc/z8run/mcp.env")
UDS = "/data/z8run/z8run.sock"
MASTER = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="


def env() -> dict[str, str]:
    out = {}
    for line in ENV.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip("'\"")
    return out


def uds_post(path: str, body: dict) -> tuple[int, str]:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect(UDS)
    raw = json.dumps(body).encode()
    req = (
        f"POST {path} HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\n"
        f"content-length: {len(raw)}\r\nconnection: close\r\n\r\n"
    ).encode() + raw
    s.sendall(req)
    data = b""
    while True:
        part = s.recv(65536)
        if not part:
            break
        data += part
    s.close()
    head, _, payload = data.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1]) if head else 0
    return status, payload.decode(errors="replace")


def main() -> int:
    cfg = env()
    base = cfg.get("Z8_BASE_URL", "http://127.0.0.1:7700").rstrip("/")
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )

    def request(method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            base + path, data=data, method=method, headers={"content-type": "application/json"}
        )
        with opener.open(req, timeout=30) as resp:
            raw = resp.read()
        return json.loads(raw) if raw else {}

    request("POST", "/auth/login", {"email": cfg["Z8_EMAIL"], "password": cfg["Z8_PASSWORD"]})
    flows = request("GET", "/api/v1/flows")
    items = flows.get("flows", flows) if isinstance(flows, dict) else flows
    flow = next((f for f in items if f.get("name") == "Z8-PROXY"), None)
    assert flow, "Z8-PROXY Flow fehlt"
    fid = flow["id"]
    request("POST", f"/api/v1/flows/{fid}/start")
    try:
        payload = {
            "addr_space": "proxy-e2e",
            "addr_user": "demo-user",
            "master_key_b64": MASTER,
            "workspace_bucket": "workspaces/proxy-e2e/",
            "engines": ["demo"],
            "dbs": ["demo"],
        }
        status, text = uds_post(f"/hook/{fid}/proxy-demo", payload)
        print(f"TRIGGER status={status}")
        try:
            body = json.loads(text)
        except ValueError:
            body = {}
        token = body.get("proxy_token") or ""
        if token:
            conn = http.client.HTTPConnection("127.0.0.1", 7800, timeout=10)
            conn.request(
                "POST",
                "/v1/session/logout",
                headers={"authorization": f"Bearer {token}"},
            )
            conn.getresponse().read()
            conn.close()
        # Kein Token in Logs: vor der Ausgabe ersetzen.
        safe = text.replace(token, "<redacted>") if token else text
        print(f"BODY {safe[:1200]}")
        assert status == 200, status
        assert '"rows"' in text and '"ok"' in text, text
        assert "PROXY-DEMO-SYSTEMPROMPT-2026" not in text
        assert token not in safe
        print("RESULT PASS")
        return 0
    finally:
        request("POST", f"/api/v1/flows/{fid}/stop")


if __name__ == "__main__":
    raise SystemExit(main())
