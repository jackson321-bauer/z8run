#!/usr/bin/env python3
"""E2E: MCP z8_proxy Logging-Aktionen (span_query, meta_query, trace_full,
export_otel) gegen den laufenden Proxy; EIN Trace Login->Proxy->Engine."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP_DIR = os.environ.get("MCP_DIR", str(ROOT / "bins" / "z8-export" / "mcp"))
sys.path.insert(0, MCP_DIR)
import z8_proxy_run  # noqa: E402

MASTER = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="
TRACE = "aabbccddeeff00112233445566778899"
TP = f"00-{TRACE}-0011223344556677-01"


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
call = fake.fn

opened = call(
    "session_open",
    addr_space="proxy2a-mcp",
    addr_user="mcp",
    master_key_b64=MASTER,
    dbs=["demo"],
    open_dbs=True,
    traceparent=TP,
)
print("SESSION_OPEN", {k: opened.get(k) for k in ("status", "ok", "trace_id", "dbs")})
assert opened["status"] == 200 and opened.get("trace_id") == TRACE, opened
token = opened["token"]

echo = call("app_call", token=token, app="echo", input={"mcp": True}, traceparent=TP)
print("APP_CALL", echo.get("status"), echo.get("app"))
assert echo["status"] == 200, echo

spans = call("span_query", token=token, trace_id=TRACE, traceparent=TP)
names = [s.get("name") for s in spans.get("spans", [])]
print("SPAN_QUERY", spans.get("status"), names)
assert spans["status"] == 200 and "app.call" in names, spans

meta = call("meta_query", token=token, trace_id=TRACE, traceparent=TP)
actions = [m.get("action") for m in (meta if isinstance(meta, list) else meta.get("meta", []))]
print("META_QUERY", actions)
assert "login" in actions and "app_call" in actions, actions

full = call("trace_full", token=token, trace_id=TRACE, traceparent=TP)
print("TRACE_FULL", full.get("span_count"), full.get("meta_count"))
assert full["status"] == 200 and full.get("span_count", 0) >= 1 and full.get("meta_count", 0) >= 1, full

exp = call("export_otel", token=token, trace_id=TRACE, traceparent=TP)
print("EXPORT_OTEL", exp.get("status"), len(exp.get("files", [])), bool(exp.get("sealed")))
assert exp["status"] == 200 and exp.get("sealed"), exp

closed = call("session_close", token=token, traceparent=TP)
print("SESSION_CLOSE", closed.get("status"))
assert closed["status"] == 200, closed
print("RESULT PASS")
