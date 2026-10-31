"""MCP-Tool z8_proxy: duenne Steuerung des nativen Proxy-Dienstes.

Spricht den Admin-UDS (0600) bzw. die lokale HTTP-API. Der Masterkey wird
nur bei session_open uebergeben, nie zurueckgegeben und nie geloggt.
"""

from __future__ import annotations

import json
import os
import socket
from typing import Any

ADMIN_SOCK = os.environ.get("KV_PROXY_ADMIN_SOCK", "/data/z8run/kv-proxy-admin.sock")
HOST = os.environ.get("KV_PROXY_BIND", "127.0.0.1")
PORT = int(os.environ.get("KV_PROXY_PORT", "7800"))


def _parse(data: bytes) -> dict[str, Any]:
    head, _, body = data.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1]) if head else 0
    try:
        parsed = json.loads(body) if body else {}
    except ValueError:
        parsed = {"raw": body.decode(errors="replace")}
    return {"status": status, **parsed}


def _uds(
    method: str,
    uri: str,
    body: dict[str, Any] | None = None,
    token: str = "",
    traceparent: str = "",
) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(60)
    s.connect(ADMIN_SOCK)
    payload = json.dumps(body).encode() if body is not None else b""
    head = f"{method} {uri} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n"
    if payload:
        head += f"content-type: application/json\r\ncontent-length: {len(payload)}\r\n"
    if token:
        head += f"authorization: Bearer {token}\r\n"
    if traceparent:
        head += f"traceparent: {traceparent}\r\n"
    s.sendall(head.encode() + b"\r\n" + payload)
    data = b""
    while True:
        part = s.recv(65536)
        if not part:
            break
        data += part
    s.close()
    return _parse(data)


def _tcp(
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    token: str = "",
    traceparent: str = "",
) -> dict:
    import http.client

    conn = http.client.HTTPConnection(HOST, PORT, timeout=60)
    headers: dict[str, str] = {}
    if token:
        headers["authorization"] = f"Bearer {token}"
    if traceparent:
        headers["traceparent"] = traceparent
    payload = json.dumps(body) if body is not None else None
    if payload:
        headers["content-type"] = "application/json"
    conn.request(method, path, body=payload, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    try:
        parsed = json.loads(raw) if raw else {}
    except ValueError:
        parsed = {"raw": raw.decode(errors="replace")}
    return {"status": resp.status, **parsed}


def _admin(
    method: str,
    uri: str,
    body: dict[str, Any] | None = None,
    token: str = "",
    traceparent: str = "",
) -> dict:
    try:
        return _uds(method, uri, body, token, traceparent)
    except OSError:
        return _tcp(method, uri, body, token, traceparent)


def register_proxy_tool(mcp) -> None:
    @mcp.tool()
    def z8_proxy(
        action: str,
        addr_space: str = "",
        addr_user: str = "",
        master_key_b64: str = "",
        dbs: list[str] | None = None,
        open_dbs: bool = False,
        token: str = "",
        app: str = "",
        input: Any = None,
        trace_id: str = "",
        action_filter: str = "",
        limit: int = 1000,
        traceparent: str = "",
    ) -> dict:
        """Proxy-Aktion: status|session_open|session_close|app_list|app_call|
        stream_open|span_query|meta_query|export_otel|trace_full.
        session_open braucht addr_space + master_key_b64 (Login-Scope); der
        Master wird nie in der Antwort ausgegeben. app_call nutzt Token +
        App-Name + input. trace_full liefert ALLE Spans+Metas eines Traces
        (beide Welten). span_query/meta_query filtern nach trace_id;
        export_otel schreibt JSONL + gesiegeltes MANIFEST.
        """
        if action == "status":
            return _admin("GET", "/v1/status", traceparent=traceparent)
        if action == "session_open":
            return _admin(
                "POST",
                "/v1/admin/session",
                {
                    "addr_space": addr_space,
                    "addr_user": addr_user,
                    "master_key_b64": master_key_b64,
                    "dbs": dbs or [],
                    "open_dbs": open_dbs,
                    "traceparent": traceparent,
                },
                traceparent=traceparent,
            )
        if action == "session_close":
            return _admin("POST", "/v1/session/logout", token=token, traceparent=traceparent)
        if action == "app_list":
            return _admin("GET", "/v1/apps", token=token, traceparent=traceparent)
        if action == "app_call":
            return _admin(
                "POST",
                "/v1/app/call",
                {"app": app, "input": input if input is not None else {}},
                token=token,
                traceparent=traceparent,
            )
        if action == "stream_open":
            return _admin("GET", "/v1/stream/blob/meta", token=token, traceparent=traceparent)
        if action == "span_query":
            return _admin("GET", f"/v1/spans?trace_id={trace_id}", token=token, traceparent=traceparent)
        if action == "trace_full":
            return _admin("GET", f"/v1/trace/full?trace_id={trace_id}", token=token, traceparent=traceparent)
        if action == "meta_query":
            body: dict[str, Any] = {"limit": limit}
            if trace_id:
                body["trace_id"] = trace_id
            if action_filter:
                body["action"] = action_filter
            return _admin("POST", "/v1/meta/query", body, token=token, traceparent=traceparent)
        if action == "export_otel":
            return _admin(
                "POST",
                "/v1/export/otel",
                {"trace_id": trace_id} if trace_id else {},
                token=token,
                traceparent=traceparent,
            )
        return {"status": 400, "code": "ACTION", "error": f"unbekannt: {action}"}
