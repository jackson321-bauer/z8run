"""MCP-Tool z8_setup: lokale Setup-API über den Unix-Socket-Hook.

Setup-Keys verlassen den Rechner nicht: der Aufrufer gibt DATEIPFADE an,
das Tool liest die PEMs, signiert damit und schickt nur die Signatur mit.
PEM-Inhalte werden aus der Antwort entfernt (nur Pfade bleiben).
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

SOCK = os.environ.get("Z8_UDS_PATH", "/data/z8run/z8run.sock")
SETUP_DIR = Path("/etc/z8run/setup-keys").resolve()
FLOW_INITIAL = os.environ.get("Z8_SETUP_FLOW_ID", "")
FLOW_OPERATION = os.environ.get("Z8_SETUP_OPERATION_FLOW_ID", "")

OPS = {
    "rotate": ("rotate", "/rotate-s3"),
    "plugin": ("plugin", "/plugin-add"),
    "pubkey": ("pubkey", "/user-pubkey-add"),
}


def _erlaubte_pems(paths: list[str]) -> list[str]:
    out = []
    for p in paths:
        resolved = Path(p).resolve()
        if not resolved.is_relative_to(SETUP_DIR):
            raise ValueError(f"Setup-PEM muss unter {SETUP_DIR} liegen: {p}")
        if not resolved.is_file():
            raise ValueError(f"Setup-PEM fehlt: {p}")
        out.append(resolved.read_text())
    if len(out) < 2:
        raise ValueError("mindestens 2 Setup-PEMs nötig (2-of-N)")
    return out


def _auth(op: str, space: str, pems: list[str]) -> dict[str, Any]:
    signed = f"{op}:{space}:{os.urandom(8).hex()}"
    key = serialization.load_pem_private_key(pems[0].encode(), password=None)
    sig = key.sign(signed.encode(), ec.ECDSA(hashes.SHA256()))
    return {
        "setup_pems": pems,
        "setup_signed": signed,
        "setup_signature": base64.b64encode(sig).decode(),
    }


def _redigiere(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k == "pem" and isinstance(v, str):
                out[k] = "<redigiert: siehe path>"
            elif k == "key_hex":
                continue
            else:
                out[k] = _redigiere(v)
        return out
    if isinstance(value, list):
        return [_redigiere(v) for v in value]
    return value


def _post(flow_id: str, path: str, body: dict) -> tuple[int, Any]:
    if not flow_id:
        raise ValueError("Flow-ID fehlt (Z8_SETUP_FLOW_ID/Z8_SETUP_OPERATION_FLOW_ID)")
    transport = httpx.HTTPTransport(uds=SOCK)
    with httpx.Client(transport=transport, base_url="http://localhost", timeout=300.0) as c:
        r = c.post(f"/hook/{flow_id}{path}", json=body)
        try:
            data = r.json()
        except ValueError:
            data = {"raw": r.text[:2000]}
        return r.status_code, data


def perform_setup(
    action: str,
    space: str = "",
    spec: dict[str, Any] | None = None,
    setup_pem_paths: list[str] | None = None,
    new_s3: dict[str, Any] | None = None,
    user: str = "",
    plugin: str = "",
    pub_b64: str = "",
    s3_prefix: str = "",
    delete_old: bool = False,
) -> dict[str, Any]:
    action = action.lower().strip()
    try:
        if action == "initial":
            body = dict(spec or {})
            if s3_prefix:
                body["s3"] = {**body.get("s3", {}), "prefix": s3_prefix}
            status, data = _post(FLOW_INITIAL, "/setup", body)
        elif action in OPS:
            op, path = OPS[action]
            pems = _erlaubte_pems(setup_pem_paths or [])
            body: dict[str, Any] = {"s3": {"prefix": s3_prefix}}
            if space:
                body["space"] = space
            if action == "rotate":
                body["newS3"] = new_s3 or {}
                body["deleteOld"] = delete_old
            elif action == "plugin":
                body["user"] = user
                body["plugin"] = plugin
            elif action == "pubkey":
                body["user"] = user
                body["pub_b64"] = pub_b64
            body.update(_auth(op, space, pems))
            status, data = _post(FLOW_OPERATION, path, body)
        else:
            return {"ok": False, "error": f"action muss initial|rotate|plugin|pubkey sein, nicht {action}"}
    except (ValueError, OSError) as e:
        return {"ok": False, "error": str(e)}
    return {"ok": status < 400, "status": status, "body": _redigiere(data)}


def register_setup_tool(mcp) -> None:
    @mcp.tool()
    def z8_setup(
        action: str,
        space: str = "",
        spec: dict[str, Any] | None = None,
        setup_pem_paths: list[str] | None = None,
        new_s3: dict[str, Any] | None = None,
        user: str = "",
        plugin: str = "",
        pub_b64: str = "",
        s3_prefix: str = "",
        delete_old: bool = False,
    ) -> dict[str, Any]:
        """Lokale Setup-API (UDS): initial | rotate | plugin | pubkey.

        initial: spec = {space, users:[{name,password,engines}], setupKeys, s3}
        rotate:  new_s3 = {prefix|host|region|bucket|access_key|secret_key}
        plugin:  user + plugin
        pubkey:  user + pub_b64
        Setup-PEMs werden NUR als Pfade unter /etc/z8run/setup-keys übergeben.
        Die Signatur wird hier erzeugt; PEM-Inhalte verlassen den Rechner nicht.
        """
        return perform_setup(
            action=action, space=space, spec=spec, setup_pem_paths=setup_pem_paths,
            new_s3=new_s3, user=user, plugin=plugin, pub_b64=pub_b64,
            s3_prefix=s3_prefix, delete_old=delete_old,
        )
