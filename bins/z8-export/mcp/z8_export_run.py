"""Export/build/run helper for the z8run MCP bridge.

Calls the real `z8-export` CLI. No REST API and no z8run server process
are involved; the generated binary runs the real z8run-core engine.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


def export_binary() -> str:
    configured = os.environ.get("Z8_EXPORT_BIN")
    if configured:
        return configured
    found = shutil.which("z8-export")
    if found:
        return found
    return "/usr/local/bin/z8-export"


def export_flow(
    flow_id: str,
    target: str = "native",
    mode: str = "cli",
    build: bool = True,
    input_json: str | dict[str, Any] | None = None,
) -> dict:
    if mode not in ("cli", "server"):
        return {"ok": False, "error": f"ungültiger mode: {mode} (cli|server)"}
    if target not in ("native", "wasm"):
        return {"ok": False, "error": f"ungültiges target: {target} (native|wasm)"}

    exporter = export_binary()
    if not Path(exporter).is_file():
        return {"ok": False, "error": f"z8-export nicht gefunden: {exporter}"}

    db_path = os.environ.get("Z8_EXPORT_DB", "/data/z8run/data/z8run.db")
    out_base = Path(os.environ.get("Z8_EXPORT_DIR", "/data/z8run/exports"))
    out_dir = out_base / str(flow_id)

    cmd = [
        exporter,
        "--db",
        db_path,
        "--flow-id",
        str(flow_id),
        "--out",
        str(out_dir),
        "--mode",
        mode,
        "--target",
        target,
    ]
    if build:
        cmd.append("--build")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Export/Build-Timeout (1800s)", "cmd": cmd}

    if proc.returncode != 0:
        return {
            "ok": False,
            "error": f"z8-export Exit {proc.returncode}",
            "cmd": cmd,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-4000:],
        }

    try:
        summary = json.loads(proc.stdout)
    except ValueError:
        summary = {"raw_stdout": proc.stdout[-4000:]}

    result: dict[str, Any] = {"ok": True, "cmd": cmd, **summary}
    binary = summary.get("binary")
    if binary and Path(binary).is_file():
        data = Path(binary).read_bytes()
        result["binary_sha256"] = hashlib.sha256(data).hexdigest()
        result["binary_bytes"] = len(data)

    if input_json is not None:
        result["run"] = _run_binary(binary, input_json)
    return result


def _run_binary(binary: str | None, input_json: Any) -> dict:
    if not binary or not Path(binary).is_file():
        return {"ok": False, "error": "kein Binary gebaut"}
    run_input = (
        json.dumps(input_json) if isinstance(input_json, (dict, list)) else str(input_json)
    )
    try:
        run = subprocess.run(
            [binary], input=run_input, capture_output=True, text=True, timeout=300
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Binary-Timeout (300s)"}
    try:
        parsed: Any = json.loads(run.stdout)
    except ValueError:
        parsed = run.stdout
    return {
        "ok": run.returncode == 0,
        "exit": run.returncode,
        "stdout": parsed,
        "stderr": run.stderr[-4000:],
    }


def register_export_tool(mcp: Any) -> None:
    """Registers the z8_export_flow tool on a FastMCP instance."""

    @mcp.tool()
    def z8_export_flow(
        flow_id: str,
        target: str = "native",
        mode: str = "cli",
        build: bool = True,
        input_json: str | dict[str, Any] | None = None,
    ) -> dict:
        """Export a flow as a standalone project, optionally build and run it."""
        return export_flow(
            flow_id, target=target, mode=mode, build=build, input_json=input_json
        )
