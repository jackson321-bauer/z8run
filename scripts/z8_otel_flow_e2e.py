#!/usr/bin/env python3
"""E2E: Z8-OTEL-Flow (login -> kv-proxy -> kv-otel -> Antwort) ueber UDS."""
from __future__ import annotations

import http.client, http.cookiejar, json, socket, urllib.request
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
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(30); s.connect(UDS)
    raw = json.dumps(body).encode()
    req = (f"POST {path} HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\n"
           f"content-length: {len(raw)}\r\nconnection: close\r\n\r\n").encode() + raw
    s.sendall(req)
    data = b""
    while True:
        part = s.recv(65536)
        if not part: break
        data += part
    s.close()
    head, _, payload = data.partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]) if head else 0, payload.decode(errors="replace")


def main() -> int:
    cfg = env()
    base = cfg.get("Z8_BASE_URL", "http://127.0.0.1:7700").rstrip("/")
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, method=method,
                                     headers={"content-type": "application/json"})
        with opener.open(req, timeout=30) as resp:
            raw = resp.read()
        return json.loads(raw) if raw else {}

    request("POST", "/auth/login", {"email": cfg["Z8_EMAIL"], "password": cfg["Z8_PASSWORD"]})
    flows = request("GET", "/api/v1/flows")
    items = flows.get("flows", flows) if isinstance(flows, dict) else flows
    flow = next((f for f in items if f.get("name") == "Z8-OTEL"), None)
    assert flow, "Z8-OTEL Flow fehlt"
    fid = flow["id"]
    request("POST", f"/api/v1/flows/{fid}/start")
    try:
        payload = {"addr_space": "otel-e2e", "addr_user": "otel-user",
                   "master_key_b64": MASTER, "workspace_bucket": "workspaces/otel-e2e/",
                   "engines": ["demo"], "dbs": ["demo"]}
        status, text = uds_post(f"/hook/{fid}/otel-demo", payload)
        print(f"TRIGGER status={status}")
        body = {}
        try: body = json.loads(text)
        except ValueError: pass
        token = body.get("proxy_token") or ""
        if token:
            conn = http.client.HTTPConnection("127.0.0.1", 7800, timeout=10)
            conn.request("POST", "/v1/session/logout", headers={"authorization": f"Bearer {token}"})
            conn.getresponse().read(); conn.close()
        safe = text.replace(token, "<redacted>") if token else text
        print(f"BODY {safe[:1500]}")
        assert status == 200, status
        res = body.get("otel_result") or {}
        assert body.get("otel_status") == 200, body.get("otel_status")
        assert res.get("trace_id") == (body.get("proxy_result") or {}).get("trace_id"), res
        assert res.get("meta_count", 0) >= 1, res
        assert token not in safe
        print("RESULT PASS")
        return 0
    finally:
        request("POST", f"/api/v1/flows/{fid}/stop")


if __name__ == "__main__":
    raise SystemExit(main())
