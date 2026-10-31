#!/usr/bin/env python3
"""E2E: MCP-Tool z8_proxy gegen den laufenden Proxy (Admin-UDS + HTTP)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP_DIR = os.environ.get("MCP_DIR", str(ROOT / "bins" / "z8-export" / "mcp"))
sys.path.insert(0, MCP_DIR)
import z8_proxy_run  # noqa: E402

MASTER = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="


class FakeMCP:
    def __init__(self):
        self.fn = None

    def tool(self):
        def deco(fn):
            self.fn = fn
            return fn

        return deco


fake = FakeMCP()
z8_proxy_run.register_proxy_tool(fake)
assert fake.fn is not None
call = fake.fn

status = call("status")
print("STATUS", status)
assert status["status"] == 200 and status["apps"] >= 1, status

opened = call(
    "session_open",
    addr_space="proxy-e2e-mcp",
    addr_user="mcp",
    master_key_b64=MASTER,
    dbs=["demo"],
    open_dbs=True,
)
print("SESSION_OPEN", {k: opened[k] for k in ("status", "ok", "session_id", "dbs")})
assert opened["status"] == 200 and opened["ok"] is True, opened
assert MASTER not in str(opened), "Master in MCP-Antwort"
token = opened["token"]

apps = call("app_list", token=token)
print("APP_LIST", apps)
assert apps["status"] == 200 and any(a["name"] == "echo" for a in apps["apps"]), apps

echo = call("app_call", token=token, app="echo", input={"mcp": True})
print("APP_CALL", echo["status"], echo["payload"]["ok"], echo["payload"]["echo"])
assert echo["status"] == 200 and echo["payload"]["echo"] == {"mcp": True}, echo

stream = call("stream_open", token=token)
print("STREAM_OPEN", stream)
assert stream["status"] == 200 and stream["chunks"] == 12, stream

closed = call("session_close", token=token)
print("SESSION_CLOSE", closed)
assert closed["status"] == 200 and closed["ok"] is True, closed

dead = call("app_list", token=token)
print("AFTER_CLOSE", dead)
assert dead["status"] == 401, dead
print("RESULT PASS")
