#!/usr/bin/env python3
"""S4: MCP-Tool z8_login gegen den laufenden z8run-Server (UDS-Hook).

Legt die Login-Canvases im Server an, baut eine frische Welt + Credential
über die exportierten Setup-Server, ruft z8_login (Assertion + PEM) auf und
prüft Replay. Der HW-Shard wird vorher clientseitig geöffnet.
"""

from __future__ import annotations

import asyncio
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request

from mcp.server.fastmcp import FastMCP

import z8_webauthn_login_e2e as e2e

sys.path.insert(0, "/data/z8run/mcp")
import z8_login_run  # noqa: E402

LOG = e2e.LOG
BASE = os.environ.get("Z8_BASE_URL", "http://127.0.0.1:7700").rstrip("/")
ENV_FILE = "/etc/z8run/mcp.env"
TOKEN = ""


def env() -> tuple[str, str]:
    vals = {}
    if os.path.isfile(ENV_FILE):
        for line in open(ENV_FILE):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                vals[k.strip()] = v.strip().strip("'\"")
    return (os.environ.get("Z8_EMAIL") or vals.get("Z8_EMAIL", ""),
            os.environ.get("Z8_PASSWORD") or vals.get("Z8_PASSWORD", ""))


def req(op, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    if data:
        r.add_header("content-type", "application/json")
    if TOKEN:
        r.add_header("authorization", f"Bearer {TOKEN}")
    try:
        with op.open(r) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{method} {path}: HTTP {e.code}: {e.read()[:400]!r}")


def login_api():
    global TOKEN
    email, password = env()
    if not email or not password:
        raise SystemExit("Z8_EMAIL/Z8_PASSWORD fehlen")
    op = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    data = json.dumps({"email": email, "password": password}).encode()
    r = urllib.request.Request(BASE + "/auth/login", data=data, method="POST")
    r.add_header("content-type", "application/json")
    with op.open(r) as resp:
        cookie = resp.headers.get("set-cookie", "")
    TOKEN = next((p.split("=", 1)[1] for p in cookie.split(";")
                  if p.strip().startswith("z8_session=")), "")
    if not TOKEN:
        raise SystemExit("kein z8_session")
    return op


def upsert(op, flow_file: str) -> str:
    j = json.load(open(flow_file))
    name = j["name"]
    nodes = j["metadata"]["positions"]["canvas_nodes"]
    edges = j["metadata"]["positions"]["canvas_edges"]
    flows = req(op, "GET", "/api/v1/flows")["flows"]
    found = next((f for f in flows if f["name"] == name), None)
    if found:
        fid = found["id"]
        req(op, "PUT", f"/api/v1/flows/{fid}", {
            "canvas_nodes": nodes, "canvas_edges": edges,
            "viewport": {"x": 0, "y": 0, "zoom": 1.0}})
    else:
        fid = req(op, "POST", "/api/v1/flows",
                  {"name": name, "description": j.get("description", "")})["id"]
        req(op, "PUT", f"/api/v1/flows/{fid}", {
            "canvas_nodes": nodes, "canvas_edges": edges,
            "viewport": {"x": 0, "y": 0, "zoom": 1.0}})
    req(op, "POST", f"/api/v1/flows/{fid}/start", {})
    return fid


def mcp_call(**kwargs):
    """Echter MCP-Endpunkt: registriertes Tool über FastMCP.call_tool."""
    res = asyncio.run(MCP.call_tool("z8_login", kwargs))
    # FastMCP liefert (content_blocks, structured_result).
    if isinstance(res, tuple) and len(res) == 2 and isinstance(res[1], dict):
        return res[1]
    if isinstance(res, dict):
        return res
    for block in res:
        text = getattr(block, "text", None)
        if text:
            return json.loads(text)
    return {"raw": str(res)}


def log(name, obj):
    with open(f"{LOG}/s4-{name}.json", "w") as f:
        json.dump(obj, f, indent=2)


def main():
    op = login_api()
    fid_wa = upsert(op, f"{e2e.BASE}/flows/KV3-Login-WebAuthn.flow.json")
    fid_pem = upsert(op, f"{e2e.BASE}/flows/KV3-Login-PEM.flow.json")
    print(f"[S4] Flows angelegt: webauthn={fid_wa} pem={fid_pem}")
    global MCP
    z8_login_run.FLOW_LOGIN = fid_wa
    z8_login_run.FLOW_LOGIN_PEM = fid_pem
    MCP = FastMCP("z8-webauthn-login-audit")
    z8_login_run.register_login_tool(MCP)

    password = "pw-" + os.urandom(8).hex()
    print(f"[S4] Prefix leeren: {e2e.wipe_prefix()} Objekte")
    e2e.shutil.rmtree(e2e.KEYS, ignore_errors=True)
    e2e.os.makedirs(e2e.KEYS)
    e2e.start(e2e.BIN_SETUP, e2e.SOCK_SETUP, "s4-setup")
    e2e.start(e2e.BIN_WA, e2e.SOCK_WA, "s4-webauthn")
    proxy = e2e.start_proxy()
    try:
        st, resp = e2e.unix_post(e2e.SOCK_SETUP, "/setup", {
            "space": e2e.SPACE, "s3": {"prefix": e2e.PREFIX},
            "users": [{"name": "anna", "password": password, "engines": ["demo"]}],
            "quorum": {"n": 3, "threshold": 2},
        })
        assert st == 200 and resp.get("ok"), (st, resp)
        user = resp["users"][0]
        expected = user["user_master_sha256"]
        key, pem_path, kem, cred_id, _ = e2e.register("anna", with_pqc=True)

        # Challenge-Dir muss dem z8run-User gehören (frischer Testlauf)
        e2e.shutil.rmtree("/data/z8run/login-challenges", ignore_errors=True)
        # Challenge über den laufenden z8run-Hook des Login-Canvas
        st, ch = z8_login_run._post(
            fid_wa, "/challenge", {"user": "anna", "s3": {"prefix": e2e.PREFIX}})
        if st != 200:
            raise SystemExit(f"challenge: {st} {ch}")
        shard = json.loads(e2e.subprocess.check_output([
            e2e.SG, "shard-open", "--s3-config", e2e.S3, "--prefix", e2e.PREFIX,
            "--addr", user["addr_user"], "--key", pem_path, "--kem", kem,
        ]).decode())
        assertion = e2e.assertion(key, cred_id, ch["webauthn_challenge"], 2)
        r = mcp_call(
            space=e2e.SPACE, user="anna", password=password,
            assertion=assertion, shamir_hw=shard["shamir_hw"],
            s3_prefix=e2e.PREFIX,
        )
        log("mcp-raw-assertion", r)
        assert isinstance(r, dict) and r.get("ok") and r.get("body", {}).get("master_sha256") == expected, r
        for feld in ("req", "opened_datei", "opened_block", "hw_block"):
            assert feld not in r["body"], f"Leak in MCP-Antwort: {feld}"
        log("mcp-assertion", {"status": r["status"], "master_sha256": r["body"]["master_sha256"],
                              "expected_master_sha256": expected,
                              "session_view": r["body"].get("session_view")})
        print(f"[S4] MCP z8_login ASSERTION OK master={expected[:16]}")

        # Replay: gleicher Counter unter neuer Challenge
        st, ch2 = z8_login_run._post(
            fid_wa, "/challenge", {"user": "anna", "s3": {"prefix": e2e.PREFIX}})
        replay_assertion = e2e.assertion(key, cred_id, ch2["webauthn_challenge"], 2)
        r = mcp_call(
            space=e2e.SPACE, user="anna", password=password,
            assertion=replay_assertion, shamir_hw=shard["shamir_hw"],
            s3_prefix=e2e.PREFIX,
        )
        assert not r["ok"] and r["status"] == 401, r
        log("mcp-replay", {"status": r["status"], "error": r["body"].get("error")})
        print(f"[S4] MCP z8_login REPLAY -> {r['status']}")

        # PEM-Parallelweg
        r = mcp_call(
            space=e2e.SPACE, user="anna", password=password,
            pem_path=user["pems"][0]["path"],
            pqc_dk_path=user["pems"][0]["pqc_dk_path"],
            s3_prefix=e2e.PREFIX,
        )
        assert r["ok"] and r["body"].get("master_sha256") == expected, r
        for feld in ("req", "key_pem", "pqc_dk"):
            assert feld not in r["body"], f"Leak im MCP-PEM: {feld}"
        log("mcp-pem", {"status": r["status"], "master_sha256": r["body"]["master_sha256"],
                        "expected_master_sha256": expected})
        print(f"[S4] MCP z8_login PEM OK master={expected[:16]}")

        tools = [t for t in sys.modules["z8_login_run"].__dict__]
        assert "register_login_tool" in tools
        print("== S4 MCP GRUEN ==")
    finally:
        proxy.shutdown()
        for p in e2e._procs:
            p.terminate()
        for p in e2e._procs:
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()


if __name__ == "__main__":
    main()
