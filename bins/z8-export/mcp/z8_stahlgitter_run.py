"""MCP-Tool z8_stahlgitter: Big-Bang-Migration + Gegenprobe (nur über Binary).

Keine Secrets im Ergebnis: das Binary liefert Datei-Hashes, PQC-Pubkeys und
Fehler — niemals Privatekeys. Schlüsselverzeichnisse sind auf /data, /etc
und /root beschränkt.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

BIN = os.environ.get(
    "Z8_STAHLGITTER_BIN", "/data/z8run-test/src/target/release/z8-stahlgitter"
)
ERLAUBT = (Path("/data").resolve(), Path("/etc").resolve(), Path("/root").resolve())


def _pruefe(p: str) -> str:
    r = Path(p).resolve()
    if not any(r.is_relative_to(d) for d in ERLAUBT):
        raise ValueError(f"Pfad außerhalb der erlaubten Wurzeln: {p}")
    return str(r)


def _run(args: list[str]) -> dict[str, Any]:
    if not Path(BIN).is_file():
        raise RuntimeError(f"Binary fehlt: {BIN}")
    p = subprocess.run([BIN, *args], capture_output=True, text=True, timeout=1800)
    if not p.stdout.strip():
        raise RuntimeError(f"z8-stahlgitter ohne Ausgabe: {p.stderr[-2000:]}")
    try:
        out = json.loads(p.stdout)
    except json.JSONDecodeError:
        return {"ok": p.returncode == 0, "raw": p.stdout[-4000:]}
    if p.returncode not in (0, 2):
        out["stderr"] = p.stderr[-2000:]
    return out


def register_stahlgitter_tool(mcp) -> None:
    @mcp.tool()
    def z8_stahlgitter(
        action: str,
        s3_config: str = "/etc/z8run/kv3-s3.json",
        prefix: str = "sim2/welt2/",
        keys: list[str] | None = None,
        local: list[str] | None = None,
        report: str = "",
    ) -> dict:
        """Z8-STAHLGITTER: action=migrate (Big Bang auf v3) oder verify (Gegenprobe)."""
        if action not in ("migrate", "verify"):
            raise ValueError("action muss migrate|verify sein")
        args = [action, "--s3-config", _pruefe(s3_config), "--prefix", prefix]
        for d in keys or []:
            args += ["--keys", _pruefe(d)]
        for d in local or []:
            args += ["--local", _pruefe(d)]
        if report:
            args += ["--report", _pruefe(report)]
        return _run(args)
