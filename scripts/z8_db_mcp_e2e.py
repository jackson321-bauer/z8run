#!/usr/bin/env python3
"""E2E: MCP-Tool z8_db über die lokale Engine-Binary (kein HTTP)."""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bins" / "z8-export" / "mcp"))
import z8_db_run  # noqa: E402

BASE = Path("/tmp/z8-dbbox-mcp-e2e")
MASTER = base64.b64encode(b"z8-dbbox-test-master-0123456789abcdef").decode()


class FakeMCP:
    def __init__(self):
        self.fn = None

    def tool(self):
        def deco(fn):
            self.fn = fn
            return fn

        return deco


def call(action, sql="", params=None, **kw):
    args = dict(
        action=action,
        db_id="mcp-db",
        master_key_b64=MASTER,
        sql=sql,
        params=params or [],
        session_id="mcp",
        local_dir=str(BASE),
        cluster_id="mcp",
        adapter="fs",
        storage_root=str(BASE / "storage"),
    )
    args.update(kw)
    return fake.fn(**args)


fake = FakeMCP()
z8_db_run.register_db_tool(fake)
assert fake.fn is not None
import shutil

shutil.rmtree(BASE, ignore_errors=True)
BASE.mkdir(parents=True)
results = {}
results["open"] = call("open")
results["write1"] = call("write", "CREATE TABLE IF NOT EXISTS t (x INTEGER)")
results["write2"] = call("write", "INSERT INTO t VALUES (?1)", [5])
results["query"] = call("query", "SELECT count(*) AS n FROM t")
results["schema"] = call("schema")
results["status"] = call("status")
results["sync"] = call("sync")
results["linefs_anlegen"] = call("linefs_anlegen", name="e2e.txt", art="code",
                                 text="a\nb", urheber="mcp")
results["ordner_listen"] = call("ordner_listen", eltern_id=0)
results["linefs_edit"] = call("linefs_ops", session_id="mcp-edit", ops=[
    {"op": "LinefsOeffnen", "pfad": "e2e.txt"},
    {"op": "LinefsZeileSetzen", "nr": 1, "inhalt": "A"},
    {"op": "LinefsSchliessen"},
])
results["linefs_render"] = call("linefs_rendere", pfad="e2e.txt")
print(json.dumps(results, indent=1))

assert results["open"]["status"] == 200, results["open"]
assert results["write2"]["write"]["rows_affected"] == 1, results["write2"]
assert results["query"]["query"]["rows"][0][0] == 1, results["query"]
names = [t["name"] for t in results["schema"]["schema"]["tables"]]
assert "t" in names, results["schema"]
assert results["sync"]["progress"]["wal_pending"] == 0, results["sync"]
assert results["linefs_anlegen"]["status"] == 200, results["linefs_anlegen"]
assert results["linefs_edit"]["status"] == 200, results["linefs_edit"]
assert results["linefs_render"]["ergebnis"]["text"] == "A\nb", results["linefs_render"]
assert results["ordner_listen"]["ergebnis"]["eintraege"], results["ordner_listen"]
blob = json.dumps(results)
assert MASTER not in blob, "Masterkey in MCP-Antwort!"
print("MCP-E2E GRUEN: write+query+schema+status+sync, kein Masterkey in Antwort")
