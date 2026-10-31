#!/usr/bin/env python3
"""Legt den Z8-PROXY-Demo-Flow im laufenden Canvas an (oder aktualisiert ihn)."""
from __future__ import annotations

import http.cookiejar
import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FLOW = ROOT / "crates" / "z8run-core" / "tests" / "fixtures" / "proxy-demo.flow.json"
ENV = Path("/etc/z8run/mcp.env")


def env() -> dict[str, str]:
    out = {}
    for line in ENV.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip("'\"")
    return out


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

    request(
        "POST",
        "/auth/login",
        {"email": cfg["Z8_EMAIL"], "password": cfg["Z8_PASSWORD"]},
    )
    doc = json.loads(FLOW.read_text())
    nodes = doc["metadata"]["positions"]["canvas_nodes"]
    edges = doc["metadata"]["positions"]["canvas_edges"]
    flows = request("GET", "/api/v1/flows")
    items = flows.get("flows", flows) if isinstance(flows, dict) else flows
    existing = next((f for f in items if f.get("name") == doc["name"]), None)
    if existing:
        fid = existing["id"]
        print(f"UPDATE flow={fid}")
    else:
        created = request(
            "POST", "/api/v1/flows", {"name": doc["name"], "description": doc["description"]}
        )
        fid = created["id"]
        print(f"CREATE flow={fid}")
    request("PUT", f"/api/v1/flows/{fid}", {"canvas_nodes": nodes, "canvas_edges": edges})
    check = request("GET", f"/api/v1/flows/{fid}")
    got = (
        check.get("canvas_nodes")
        or check.get("metadata", {}).get("positions", {}).get("canvas_nodes", [])
    )
    types = [n["data"]["type"] for n in got]
    assert types == ["unix-in", "kv-proxy", "db-query", "http-out"], types
    xs = [n["position"]["x"] for n in got]
    assert xs == sorted(xs) and len(set(xs)) == len(xs), xs
    print(f"VERIFIED flow={fid} nodes={types} xs={xs}")
    print("RESULT PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
