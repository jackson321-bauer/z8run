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
    blob_id: str = "",
    datei_pfad: str = "",
    base64: str = "",
    name: str = "",
    mime: str = "",
    owner: str = "mcp",
    ziel_adapter: str = "",
    op: str = "",
    pfad: str = "",
    nr: int = 0,
    inhalt: str = "",
    eltern_id: int = 0,
    neu: str = "",
    muster: str = "",
    suche: str = "",
    ersatz: str = "",
    fassung: int = 0,
    schluessel: int | None = None,
    prozess_id: str = "",
    ops: list[Any] | None = None,
    art: str = "code",
    text: str = "",
    urheber: str = "mcp",
    ordner_id: int = 0,
) -> dict[str, Any]:
    return {
        "action": action,
        "art": art,
        "text": text,
        "urheber": urheber,
        "ordner_id": ordner_id,
        "op": op,
        "pfad": pfad,
        "nr": nr,
        "inhalt": inhalt,
        "eltern_id": eltern_id,
        "neu": neu,
        "muster": muster,
        "suche": suche,
        "ersatz": ersatz,
        "fassung": fassung,
        "schluessel": schluessel,
        "prozess_id": prozess_id,
        "ops": ops or [],
        "db_id": db_id,
        "master_key_b64": master_key_b64,
        "sql": sql,
        "params": params or [],
        "session_id": session_id,
        "localDir": local_dir,
        "clusterId": cluster_id,
        "adapter": adapter,
        "storageRoot": storage_root,
        "bucket": bucket,
        "prefix": prefix,
        "blob_id": blob_id,
        "datei_pfad": datei_pfad,
        "base64": base64,
        "name": name,
        "mime": mime,
        "owner": owner,
        "ziel_adapter": ziel_adapter,
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
        blob_id: str = "",
        datei_pfad: str = "",
        base64: str = "",
        name: str = "",
        mime: str = "",
        owner: str = "mcp",
        ziel_adapter: str = "",
        op: str = "",
        pfad: str = "",
        nr: int = 0,
        inhalt: str = "",
        eltern_id: int = 0,
        neu: str = "",
        muster: str = "",
        suche: str = "",
        ersatz: str = "",
        fassung: int = 0,
        schluessel: int | None = None,
        prozess_id: str = "",
        ops: list[Any] | None = None,
        art: str = "code",
        text: str = "",
        urheber: str = "mcp",
        ordner_id: int = 0,
    ) -> dict[str, Any]:
        """DB-Node-Aktion: open|query|write|schema|status|sync|
        blob_put|blob_get|blob_list|blob_delete sowie die volle
        LineFS-/Ordner-Matrix: linefs_anlegen|linefs_open|linefs_read|
        linefs_write|linefs_insert|linefs_delete|linefs_close|
        linefs_render|linefs_pages|linefs_history|linefs_verify|
        linefs_rename|linefs_blob_put|linefs_blob_get|linefs_blob_show|
        ordner_anlegen|ordner_verschieben|ordner_umbenennen|
        ordner_listen|ordner_pfad_aufloesen. Mit action="linefs_ops"
        laesst sich eine ops-Liste (open/write/close) in EINEM Prozess
        ausfuehren.

        master_key_b64 kommt aus dem Login/Proxy-Scope und wird NIE in der
        Antwort ausgegeben. query ist readonly; write/blob_put/blob_delete
        reservieren/releasen selbst (Ein-Schreiber-Regel bleibt in der
        Engine). blob_get liefert Klartext nur an den authentisierten
        Aufrufer: Datei-Ziel (ziel_adapter) oder base64 in der Antwort.
        """
        return _run(
            _payload(
                action, db_id, master_key_b64, sql, params, session_id,
                local_dir, cluster_id, adapter, storage_root, bucket, prefix,
                blob_id, datei_pfad, base64, name, mime, owner, ziel_adapter,
                op, pfad, nr, inhalt, eltern_id, neu, muster, suche, ersatz,
                fassung, schluessel, prozess_id, ops, art, text, urheber, ordner_id,
            )
        )
