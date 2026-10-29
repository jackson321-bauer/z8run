#!/usr/bin/env python3
"""Legt die Z8-Setup-Flows (Canvas) auf einem z8run-Server an/aktualisiert sie.

Keine Secrets im Skript: Zugang kommt aus Z8_BASE_URL/Z8_EMAIL/Z8_PASSWORD.
Die Node-Configs enthalten nur Dateipfade und Formatwerte.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
import http.cookiejar

BASE = os.environ.get("Z8_BASE_URL", "http://127.0.0.1:7700").rstrip("/")
EMAIL = os.environ.get("Z8_EMAIL", "")
PASSWORD = os.environ.get("Z8_PASSWORD", "")

from z8setup_flowdefs import initial_flow, operation_flow, webauthn_flow


def _opener() -> urllib.request.OpenerDirector:
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


TOKEN = ""


def _req(op, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    if data:
        r.add_header("content-type", "application/json")
    if TOKEN:
        r.add_header("authorization", f"Bearer {TOKEN}")
    try:
        with op.open(r) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{method} {path}: HTTP {e.code}: {e.read()[:400]!r}")


def upsert(op, name, desc, nodes, edges):
    flows = _req(op, "GET", "/api/v1/flows")["flows"]
    found = next((f for f in flows if f["name"] == name), None)
    if found:
        fid = found["id"]
        _req(op, "PUT", f"/api/v1/flows/{fid}", {
            "canvas_nodes": nodes, "canvas_edges": edges,
            "viewport": {"x": 0, "y": 0, "zoom": 0.8}})
    else:
        created = _req(op, "POST", "/api/v1/flows", {"name": name, "description": desc})
        fid = created["id"]
        _req(op, "PUT", f"/api/v1/flows/{fid}", {
            "canvas_nodes": nodes, "canvas_edges": edges,
            "viewport": {"x": 0, "y": 0, "zoom": 0.8}})
    return fid


def main():
    if not EMAIL or not PASSWORD:
        raise SystemExit("Z8_EMAIL/Z8_PASSWORD fehlen")
    global TOKEN
    op = _opener()
    data = json.dumps({"email": EMAIL, "password": PASSWORD}).encode()
    r = urllib.request.Request(BASE + "/auth/login", data=data, method="POST")
    r.add_header("content-type", "application/json")
    with op.open(r) as resp:
        cookie = resp.headers.get("set-cookie", "")
    for part in cookie.split(";"):
        if part.strip().startswith("z8_session="):
            TOKEN = part.strip().split("=", 1)[1]
    if not TOKEN:
        raise SystemExit("Login lieferte kein z8_session")
    out = {}
    for builder in (initial_flow, operation_flow, webauthn_flow):
        name, desc, nodes, edges = builder()
        out[name] = upsert(op, name, desc, nodes, edges)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
