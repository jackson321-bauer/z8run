"""MCP-Tool z8_login: Login v2 über den Unix-Socket-Hook.

Zwei Faktoren: Passwort + WebAuthn-Assertion (Software-Passkey) ODER der
PEM-Parallelweg. Der HW-Shard wird IMMER clientseitig geöffnet; das Tool
bekommt nur den fertigen `shamir_hw`. PEMs bleiben als DATEIPFAD beim
Aufrufer — der Inhalt wird nie zurückgegeben oder geloggt.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx

SOCK = os.environ.get("Z8_UDS_PATH", "/data/z8run/z8run.sock")
FLOW_LOGIN = os.environ.get("Z8_LOGIN_FLOW_ID", "")
FLOW_LOGIN_PEM = os.environ.get("Z8_LOGIN_PEM_FLOW_ID", "")
KEY_DIRS = [
    Path("/etc/z8run/setup-keys").resolve(),
    Path("/data/z8run/setup-keys").resolve(),
]


def _datei_inhalt(path: str, art: str) -> str:
    p = Path(path).resolve()
    if not any(p.is_relative_to(d) for d in KEY_DIRS):
        raise ValueError(f"{art} muss unter {KEY_DIRS} liegen: {path}")
    if not p.is_file():
        raise ValueError(f"{art} fehlt: {path}")
    return p.read_text()


def _post(flow_id: str, path: str, body: dict) -> tuple[int, Any]:
    if not flow_id:
        raise ValueError("Flow-ID fehlt (Z8_LOGIN_FLOW_ID/Z8_LOGIN_PEM_FLOW_ID)")
    transport = httpx.HTTPTransport(uds=SOCK)
    with httpx.Client(transport=transport, base_url="http://localhost", timeout=300.0) as c:
        r = c.post(f"/hook/{flow_id}{path}", json=body)
        try:
            data = r.json()
        except ValueError:
            data = {"raw": r.text[:2000]}
        return r.status_code, data


def perform_login_challenge(
    space: str,
    user: str,
    s3_prefix: str = "",
    flow_id: str = "",
) -> dict[str, Any]:
    """Holt die Einmal-Challenge VOR dem Signieren (Client-Flow)."""
    try:
        body: dict[str, Any] = {"user": user}
        if s3_prefix:
            body["s3"] = {"prefix": s3_prefix}
        st, data = _post(flow_id or FLOW_LOGIN, "/challenge", body)
    except (ValueError, OSError) as e:
        return {"ok": False, "error": str(e)}
    return {"ok": st < 400, "status": st, "body": data}


def perform_login(
    space: str,
    user: str,
    password: str,
    assertion: dict[str, Any] | None = None,
    shamir_hw: dict[str, Any] | None = None,
    pem_path: str = "",
    pqc_dk_path: str = "",
    s3_prefix: str = "",
    flow_id: str = "",
    pem_flow_id: str = "",
) -> dict[str, Any]:
    try:
        s3 = {"prefix": s3_prefix} if s3_prefix else None
        if assertion:
            fid = flow_id or FLOW_LOGIN
            if not assertion.get("challenge"):
                return {
                    "ok": False,
                    "error": "assertion.challenge fehlt — zuerst z8_login_challenge aufrufen, dann signieren",
                }
            body: dict[str, Any] = {
                "space": space, "user": user, "password": password, **assertion,
            }
            if shamir_hw:
                body["shamir_hw"] = shamir_hw
            if s3:
                body["s3"] = s3
            st, data = _post(fid, "/login", body)
        elif pem_path:
            fid = pem_flow_id or FLOW_LOGIN_PEM or flow_id or FLOW_LOGIN
            body = {
                "space": space, "user": user, "password": password,
                "key_pem": _datei_inhalt(pem_path, "PEM"),
            }
            if pqc_dk_path:
                # Privater KEM-Key wird wie das PEM nur lokal gelesen; der
                # Flow bekommt den Base64-Inhalt (PEM-Parallelweg), nie
                # einen Pfad, den der Server-User nicht lesen darf.
                body["pqc_dk"] = _datei_inhalt(pqc_dk_path, "KEM-DK").strip()
            if s3:
                body["s3"] = s3
            st, data = _post(fid, "/login", body)
            body = {}
        else:
            return {"ok": False, "error": "assertion oder pem_path nötig"}
    except (ValueError, OSError) as e:
        return {"ok": False, "error": str(e)}
    return {"ok": st < 400, "status": st, "body": data}


def register_login_tool(mcp) -> None:
    @mcp.tool()
    def z8_login_challenge(
        user: str,
        space: str = "",
        s3_prefix: str = "",
    ) -> dict[str, Any]:
        """Einmal-Challenge für den Login holen (vor der Assertion signieren)."""
        return perform_login_challenge(
            space=space, user=user, s3_prefix=s3_prefix)

    @mcp.tool()
    def z8_login(
        space: str,
        user: str,
        password: str,
        assertion: dict[str, Any] | None = None,
        shamir_hw: dict[str, Any] | None = None,
        pem_path: str = "",
        pqc_dk_path: str = "",
        s3_prefix: str = "",
    ) -> dict[str, Any]:
        """Login v2: Passwort + WebAuthn-Assertion ODER PEM-Parallelweg.

        assertion = {credentialId, authenticatorData, clientDataJSON, signature}
        shamir_hw = vom CLIENT geöffneter HW-Shard {x, y_b64}; der Flow macht
        KEIN ECDH. pem_path zeigt auf eine User-PEM unter den Setup-Key-Dirs.
        Die Challenge wird intern über /challenge geholt.
        """
        return perform_login(
            space=space, user=user, password=password, assertion=assertion,
            shamir_hw=shamir_hw, pem_path=pem_path, pqc_dk_path=pqc_dk_path,
            s3_prefix=s3_prefix,
        )
