"""MCP-Tool z8_db: ruft die DB-Node-Engine über die lokale Binary auf.

Kein HTTP, keine Keys in Antworten. Der Masterkey wird als Argument
übergeben (Login/Proxy-Scope), nie zurückgegeben und nie geloggt.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any

BINARY = os.environ.get("Z8_DBNODE_BIN", "/data/z8run/bin/z8-dbnode")


def _run(payload: dict[str, Any], timeout: int = 60) -> dict[str, Any]:
    if not os.path.isfile(BINARY):
        return {"status": 400, "code": "BINARY", "error": f"nicht gefunden: {BINARY}"}
    try:
        p = subprocess.run(
            [BINARY],
            input=json.dumps(payload).encode(),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"status": 400, "code": "EXEC", "error": str(e)}
    out = p.stdout.decode(errors="replace").strip()
    try:
        data = json.loads(out) if out else {}
    except ValueError:
        data = {"status": 400, "code": "OUTPUT", "error": out[-500:]}
    if not data:
        data = {"status": 400, "code": "OUTPUT", "error": p.stderr.decode(errors="replace")[-500:]}
    return data


def _payload(
    action: str,
    db_id: str,
    master_key_b64: str,
    sql: str,
    params: list[Any] | None,
    session_id: str,
    local_dir: str,
    cluster_id: str,
    adapter: str,
    storage_root: str,
    bucket: str,
    prefix: str,
) -> dict[str, Any]:
    return {
        "action": action,
        "db_id": db_id,
        "master_key_b64": master_key_b64,
        "sql": sql,
        "params": params or [],
        "session_id": session_id,
        "local_dir": local_dir,
        "cluster_id": cluster_id,
        "adapter": adapter,
        "storage_root": storage_root,
        "bucket": bucket,
        "prefix": prefix,
    }


def register_db_tool(mcp) -> None:
    @mcp.tool()
    def z8_db(
        action: str,
        db_id: str,
        master_key_b64: str,
        sql: str = "",
        params: list[Any] | None = None,
        session_id: str = "mcp",
        local_dir: str = "/data/z8run/dbnode",
        cluster_id: str = "default",
        adapter: str = "fs",
        storage_root: str = "",
        bucket: str = "",
        prefix: str = "",
    ) -> dict[str, Any]:
        """DB-Node-Aktion: open|query|write|schema|status|sync.

        master_key_b64 kommt aus dem Login/Proxy-Scope und wird NIE in der
        Antwort ausgegeben. query ist readonly; write reserviert/released
        selbst (Ein-Schreiber-Regel bleibt in der Engine).
        """
        return _run(
            _payload(
                action, db_id, master_key_b64, sql, params, session_id,
                local_dir, cluster_id, adapter, storage_root, bucket, prefix,
            )
        )
