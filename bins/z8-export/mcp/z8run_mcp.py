#!/usr/bin/env python3
"""MCP bridge for the z8run flow engine.

The server speaks stdio MCP and forwards tool calls to z8run's REST API.
Credentials are read from /etc/z8run/mcp.env (0600) or the process env.
The model never sees the password; it only sees tool results.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

ENV_FILE = Path("/etc/z8run/mcp.env")


def _load_env() -> None:
    if not ENV_FILE.is_file():
        return
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


_load_env()

BASE_URL = os.environ.get("Z8_BASE_URL", "http://127.0.0.1:7700").rstrip("/")
EMAIL = os.environ.get("Z8_EMAIL", "")
PASSWORD = os.environ.get("Z8_PASSWORD", "")

mcp = FastMCP("z8run")
_client: httpx.Client | None = None


class Z8Error(RuntimeError):
    pass


def _login(client: httpx.Client) -> None:
    if not EMAIL or not PASSWORD:
        raise Z8Error("Z8_EMAIL/Z8_PASSWORD fehlen (siehe /etc/z8run/mcp.env)")
    response = client.post(
        "/auth/login",
        json={"email": EMAIL, "password": PASSWORD},
    )
    if response.status_code >= 400:
        raise Z8Error(f"Login fehlgeschlagen: HTTP {response.status_code}: {response.text[:400]}")


def _client_get() -> httpx.Client:
    global _client
    if _client is None:
        client = httpx.Client(base_url=BASE_URL, timeout=60.0, follow_redirects=True)
        _login(client)
        _client = client
    return _client


def _request(method: str, path: str, **kwargs: Any) -> Any:
    client = _client_get()
    response = client.request(method, path, **kwargs)
    if response.status_code == 401:
        # Session expired: log in again once and retry.
        _login(client)
        response = client.request(method, path, **kwargs)
    if response.status_code >= 400:
        raise Z8Error(f"HTTP {response.status_code} {method} {path}: {response.text[:800]}")
    if not response.content:
        return {"ok": True, "status": response.status_code}
    try:
        return response.json()
    except ValueError:
        return {"ok": True, "status": response.status_code, "body": response.text[:2000]}


@mcp.tool()
def z8_health() -> dict:
    """Health check of the z8run server."""
    return _request("GET", "/api/v1/health")


@mcp.tool()
def z8_info() -> dict:
    """Server information (version, port, active flows)."""
    return _request("GET", "/api/v1/info")


@mcp.tool()
def z8_me() -> dict:
    """Currently authenticated user."""
    return _request("GET", "/auth/me")


@mcp.tool()
def z8_list_flows() -> dict:
    """List all flows of the current user."""
    return _request("GET", "/api/v1/flows")


@mcp.tool()
def z8_get_flow(flow_id: str) -> dict:
    """Read one flow including canvas nodes/edges and metadata."""
    return _request("GET", f"/api/v1/flows/{flow_id}")


@mcp.tool()
def z8_create_flow(name: str, description: str = "") -> dict:
    """Create an empty flow and return its id."""
    return _request("POST", "/api/v1/flows", json={"name": name, "description": description})


@mcp.tool()
def z8_update_flow(
    flow_id: str,
    canvas_nodes: list[dict],
    canvas_edges: list[dict],
    viewport: dict | None = None,
) -> dict:
    """Replace the canvas of a flow (React-Flow nodes/edges)."""
    payload: dict[str, Any] = {"canvas_nodes": canvas_nodes, "canvas_edges": canvas_edges}
    if viewport is not None:
        payload["viewport"] = viewport
    return _request("PUT", f"/api/v1/flows/{flow_id}", json=payload)


@mcp.tool()
def z8_delete_flow(flow_id: str) -> dict:
    """Delete a flow."""
    return _request("DELETE", f"/api/v1/flows/{flow_id}")


@mcp.tool()
def z8_start_flow(flow_id: str) -> dict:
    """Start a flow."""
    return _request("POST", f"/api/v1/flows/{flow_id}/start")


@mcp.tool()
def z8_stop_flow(flow_id: str) -> dict:
    """Stop a running flow."""
    return _request("POST", f"/api/v1/flows/{flow_id}/stop")


@mcp.tool()
def z8_export_document(flow_id: str) -> dict:
    """Export a flow as a portable JSON document (no build)."""
    return _request("GET", f"/api/v1/flows/{flow_id}/export")


def _export_binary() -> str:
    configured = os.environ.get("Z8_EXPORT_BIN")
    if configured:
        return configured
    found = shutil.which("z8-export")
    if found:
        return found
    return "/usr/local/bin/z8-export"


@mcp.tool()
def z8_export_flow(
    flow_id: str,
    target: str = "native",
    mode: str = "cli",
    build: bool = True,
    input_json: str | dict[str, Any] | None = None,
) -> dict:
    """Export a flow as a standalone project and optionally build and run it.

    Runs the real `z8-export` CLI (path-dependency on z8run-core, no server
    process needed). Returns project path, binary path, sha256 and — when
    `input_json` is given — the binary's stdout/exit code.
    """
    if mode not in ("cli", "server"):
        return {"ok": False, "error": f"ungültiger mode: {mode} (cli|server)"}
    if target not in ("native", "wasm"):
        return {"ok": False, "error": f"ungültiges target: {target} (native|wasm)"}

    exporter = _export_binary()
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
        if not binary or not Path(binary).is_file():
            result["run"] = {"ok": False, "error": "kein Binary gebaut"}
        else:
            run_input = (
                json.dumps(input_json)
                if isinstance(input_json, (dict, list))
                else str(input_json)
            )
            try:
                run = subprocess.run(
                    [binary], input=run_input, capture_output=True, text=True, timeout=300
                )
                parsed: Any
                try:
                    parsed = json.loads(run.stdout)
                except ValueError:
                    parsed = run.stdout
                result["run"] = {
                    "ok": run.returncode == 0,
                    "exit": run.returncode,
                    "stdout": parsed,
                    "stderr": run.stderr[-4000:],
                }
            except subprocess.TimeoutExpired:
                result["run"] = {"ok": False, "error": "Binary-Timeout (300s)"}

    return result


@mcp.tool()
def z8_executions(flow_id: str) -> dict:
    """Execution history of a flow, including trace ids and node logs."""
    return _request("GET", f"/api/v1/flows/{flow_id}/executions")


@mcp.tool()
def z8_list_plugins() -> dict:
    """Installed WASM plugin nodes."""
    return _request("GET", "/api/v1/plugins")


@mcp.tool()
def z8_list_credentials() -> dict:
    """Credential names stored in the vault (never the values)."""
    return _request("GET", "/api/v1/vault")


SECRETS_DIR = Path("/etc/z8run/secrets").resolve()


@mcp.tool()
def z8_store_credential_from_file(key: str, path: str) -> dict:
    """Store a credential whose value is read from a local file.

    The secret never passes through the model; only the key and the file
    path do. Only files below /etc/z8run/secrets/ are accepted.
    """
    source = Path(path).resolve()
    if not source.is_relative_to(SECRETS_DIR):
        raise Z8Error(f"Pfad muss unter {SECRETS_DIR} liegen")
    if not source.is_file():
        raise Z8Error(f"Datei {source} existiert nicht")
    value = source.read_text().strip()
    if not value:
        raise Z8Error(f"Datei {source} ist leer")
    return _request("POST", "/api/v1/vault", json={"key": key, "value": value})


if __name__ == "__main__":
    mcp.run()
