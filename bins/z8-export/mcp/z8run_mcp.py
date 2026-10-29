#!/usr/bin/env python3
"""MCP bridge for the z8run flow engine.

The server speaks stdio MCP and forwards tool calls to z8run's REST API.
Credentials are read from /etc/z8run/mcp.env (0600) or the process env.
The model never sees the password; it only sees tool results.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from z8_export_run import register_export_tool
from z8_setup_run import register_setup_tool

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
register_export_tool(mcp)
register_setup_tool(mcp)
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
