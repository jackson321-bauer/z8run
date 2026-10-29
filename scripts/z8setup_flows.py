#!/usr/bin/env python3
"""Legt die Z8-Setup-Flows (Canvas) auf einem z8run-Server an/aktualisiert sie.

Keine Secrets im Skript: Zugang kommt aus Z8_BASE_URL/Z8_EMAIL/Z8_PASSWORD.
Die Node-Configs enthalten nur Dateipfade und Formatwerte.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
import http.cookiejar

BASE = os.environ.get("Z8_BASE_URL", "http://127.0.0.1:7700").rstrip("/")
EMAIL = os.environ.get("Z8_EMAIL", "")
PASSWORD = os.environ.get("Z8_PASSWORD", "")
S3 = "/etc/z8run/kv3-s3.json"
REG = "setup/registry.txt"
SHARDS = "setup/setup-shards.txt"


def _opener() -> urllib.request.OpenerDirector:
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


TOKEN = ""


def _req(op, method, path, body=None):
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


def node(nid, typ, label, cfg, *, error=True, trigger=False, out=False):
    data = {"type": typ, "label": label, "config": cfg}
    if trigger:
        data["inputs"] = []
        data["outputs"] = [{"id": "output", "name": "Output", "type": "object"}]
    elif out:
        data["inputs"] = [{"id": "input", "name": "Input", "type": "any"}]
        data["outputs"] = []
    else:
        data["inputs"] = [{"id": "input", "name": "Input", "type": "any"}]
        data["outputs"] = [
            {"id": "output", "name": "Output", "type": "object"},
            {"id": "error", "name": "Error", "type": "any"},
        ] if error else [{"id": "output", "name": "Output", "type": "object"}]
    return {"id": nid, "type": "z8node", "position": {"x": 0, "y": 0}, "data": data}


def edge(src, dst, port="output"):
    return {
        "id": f"e-{src}-{port}-{dst}",
        "source": src,
        "sourceHandle": port,
        "target": dst,
        "targetHandle": "input",
    }


def initial_flow():
    nodes = [
        node("in", "unix-in", "POST /setup", {"method": "POST", "path": "/setup"}, trigger=True),
        node("val", "setup-validate", "Validate (space, users, engines, quorum)", {
            "engines": "demo,fts5,vec0"}),
        node("key", "setup-keygen", "Setup-Keys erzeugen (2-of-N)", {
            "s3Config": S3, "pemCount": 3, "outDir": "/data/z8run/setup-keys",
            "registryKey": REG, "shardsKey": SHARDS}),
        node("world", "setup-world", "Welt bauen (N Userspaces, keine Shared)", {
            "s3Config": S3, "outDir": "/data/z8run/setup-keys",
            "vec0Path": "/data/z8run/vec0.so", "hwKeys": 2, "registryKey": REG}),
        node("put", "s3-put", "S3: Hashdateien + Workspaces + DBs", {
            "s3Config": S3, "filesPath": "files"}),
        node("sum", "setup-summary", "Antwort (Allowlist)", {}, error=False),
        node("out", "http-out", "200 Setup OK", {"statusCode": 200}, out=True),
        node("err-val", "http-out", "400 validate", {"statusCode": 400}, out=True),
        node("err-key", "http-out", "400 keygen", {"statusCode": 400}, out=True),
        node("err-world", "http-out", "400 world", {"statusCode": 400}, out=True),
        node("err-put", "http-out", "400 s3", {"statusCode": 400}, out=True),
    ]
    edges = [
        edge("in", "val"), edge("val", "key"), edge("key", "world"),
        edge("world", "put"), edge("put", "sum"), edge("sum", "out"),
        edge("val", "err-val", "error"), edge("key", "err-key", "error"),
        edge("world", "err-world", "error"), edge("put", "err-put", "error"),
    ]
    return "Z8-Setup", "API 0: Initial-Setup (lokal/single, N Userspaces)", nodes, edges


def operation_flow():
    nodes = [
        node("in-rot", "unix-in", "POST /rotate-s3", {"method": "POST", "path": "/rotate-s3"}, trigger=True),
        node("auth-rot", "setup-auth", "Setup-Key-Auth (rotate)", {
            "s3Config": S3, "registryKey": REG, "shardsKey": SHARDS, "op": "rotate"}),
        node("rot", "rotate-s3", "S3 rotieren (Boxen mitnehmen)", {
            "s3Config": S3, "registryKey": REG}),
        node("res-rot", "setup-result", "Ergebnis rotate", {}, error=False),
        node("out-rot", "http-out", "200 rotate", {"statusCode": 200}, out=True),
        node("aerr-rot", "http-out", "403 rotate", {"statusCode": 403}, out=True),
        node("rerr-rot", "http-out", "400 rotate", {"statusCode": 400}, out=True),

        node("in-plg", "unix-in", "POST /plugin-add", {"method": "POST", "path": "/plugin-add"}, trigger=True),
        node("auth-plg", "setup-auth", "Setup-Key-Auth (plugin)", {
            "s3Config": S3, "registryKey": REG, "shardsKey": SHARDS, "op": "plugin"}),
        node("plg", "plugin-add", "Plugin freigeben", {
            "s3Config": S3, "registryKey": REG}),
        node("res-plg", "setup-result", "Ergebnis plugin", {}, error=False),
        node("out-plg", "http-out", "200 plugin", {"statusCode": 200}, out=True),
        node("aerr-plg", "http-out", "403 plugin", {"statusCode": 403}, out=True),
        node("rerr-plg", "http-out", "400 plugin", {"statusCode": 400}, out=True),

        node("in-pk", "unix-in", "POST /user-pubkey-add", {"method": "POST", "path": "/user-pubkey-add"}, trigger=True),
        node("auth-pk", "setup-auth", "Setup-Key-Auth (pubkey)", {
            "s3Config": S3, "registryKey": REG, "shardsKey": SHARDS, "op": "pubkey"}),
        node("pk", "user-pubkey-add", "HW-Pubkey registrieren", {
            "s3Config": S3, "registryKey": REG}),
        node("res-pk", "setup-result", "Ergebnis pubkey", {}, error=False),
        node("out-pk", "http-out", "200 pubkey", {"statusCode": 200}, out=True),
        node("aerr-pk", "http-out", "403 pubkey", {"statusCode": 403}, out=True),
        node("rerr-pk", "http-out", "400 pubkey", {"statusCode": 400}, out=True),
    ]
    edges = []
    for p, auth, op, res, ok, aerr, rerr in [
        ("rot", "auth-rot", "rot", "res-rot", "out-rot", "aerr-rot", "rerr-rot"),
        ("plg", "auth-plg", "plg", "res-plg", "out-plg", "aerr-plg", "rerr-plg"),
        ("pk", "auth-pk", "pk", "res-pk", "out-pk", "aerr-pk", "rerr-pk"),
    ]:
        edges += [
            edge(f"in-{p}", auth), edge(auth, op), edge(op, res), edge(res, ok),
            edge(auth, aerr, "error"), edge(op, rerr, "error"),
        ]
    return "Z8-Setup-Operation", "API 0: key-gated Betrieb (rotate/plugin/pubkey)", nodes, edges


def webauthn_flow():
    nodes = [
        node("in-ch", "unix-in", "POST /webauthn/challenge", {"method": "POST", "path": "/webauthn/challenge"}, trigger=True),
        node("ch", "webauthn-challenge", "Challenge erzeugen", {}, error=False),
        node("out-ch", "http-out", "200 challenge", {"statusCode": 200}, out=True),

        node("in-reg", "unix-in", "POST /webauthn/register", {"method": "POST", "path": "/webauthn/register"}, trigger=True),
        node("auth-reg", "setup-auth", "Setup-Key-Auth (webauthn-register)", {
            "s3Config": S3, "registryKey": REG, "shardsKey": SHARDS, "op": "webauthn-register"}),
        node("wreg", "webauthn-register", "WebAuthn-Registrierung prüfen", {
            "s3Config": S3, "registryKey": REG}),
        node("res-reg", "setup-result", "Ergebnis register", {}, error=False),
        node("out-reg", "http-out", "200 register", {"statusCode": 200}, out=True),
        node("aerr-reg", "http-out", "403 register", {"statusCode": 403}, out=True),
        node("werr-reg", "http-out", "403 register node", {"statusCode": 403}, out=True),

        node("in-as", "unix-in", "POST /webauthn/assert", {"method": "POST", "path": "/webauthn/assert"}, trigger=True),
        node("auth-as", "setup-auth", "Setup-Key-Auth (webauthn-assert)", {
            "s3Config": S3, "registryKey": REG, "shardsKey": SHARDS, "op": "webauthn-assert"}),
        node("was", "webauthn-assert", "WebAuthn-Assertion prüfen", {
            "s3Config": S3, "registryKey": REG}),
        node("res-as", "setup-result", "Ergebnis assert", {}, error=False),
        node("out-as", "http-out", "200 assert", {"statusCode": 200}, out=True),
        node("aerr-as", "http-out", "403 assert", {"statusCode": 403}, out=True),
        node("werr-as", "http-out", "403 assert node", {"statusCode": 403}, out=True),
    ]
    edges = [
        edge("in-ch", "ch"), edge("ch", "out-ch"),
        edge("in-reg", "auth-reg"), edge("auth-reg", "wreg"), edge("wreg", "res-reg"),
        edge("res-reg", "out-reg"), edge("auth-reg", "aerr-reg", "error"),
        edge("wreg", "werr-reg", "error"),
        edge("in-as", "auth-as"), edge("auth-as", "was"), edge("was", "res-as"),
        edge("res-as", "out-as"), edge("auth-as", "aerr-as", "error"),
        edge("was", "werr-as", "error"),
    ]
    return "Z8-Setup-WebAuthn", "API 0: WebAuthn/FIDO2-Registrierung + Assertion", nodes, edges


def upsert(op, name, desc, nodes, edges):
    flows = _req(op, "GET", "/api/v1/flows")["flows"]
    found = next((f for f in flows if f["name"] == name), None)
    if found:
        fid = found["id"]
        _req(op, "PUT", f"/api/v1/flows/{fid}", {
            "canvas_nodes": nodes, "canvas_edges": edges,
            "viewport": {"x": 0, "y": 0, "zoom": 0.8}})
    else:
        created = _req(op, "POST", "/api/v1/flows", {"name": name, "description": desc})
        fid = created["id"]
        _req(op, "PUT", f"/api/v1/flows/{fid}", {
            "canvas_nodes": nodes, "canvas_edges": edges,
            "viewport": {"x": 0, "y": 0, "zoom": 0.8}})
    return fid


def main():
    if not EMAIL or not PASSWORD:
        raise SystemExit("Z8_EMAIL/Z8_PASSWORD fehlen")
    global TOKEN
    op = _opener()
    data = json.dumps({"email": EMAIL, "password": PASSWORD}).encode()
    r = urllib.request.Request(BASE + "/auth/login", data=data, method="POST")
    r.add_header("content-type", "application/json")
    with op.open(r) as resp:
        cookie = resp.headers.get("set-cookie", "")
    for part in cookie.split(";"):
        if part.strip().startswith("z8_session="):
            TOKEN = part.strip().split("=", 1)[1]
    if not TOKEN:
        raise SystemExit("Login lieferte kein z8_session")
    out = {}
    for builder in (initial_flow, operation_flow, webauthn_flow):
        name, desc, nodes, edges = builder()
        out[name] = upsert(op, name, desc, nodes, edges)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
